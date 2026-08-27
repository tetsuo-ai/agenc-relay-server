//! Independent value-state model for pure domain state-machine tests.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

const MAX_REFERENCE_ACCOUNTS: usize = 64;
const MAX_REFERENCE_SESSIONS: usize = 256;
const MAX_REFERENCE_CHANNELS: usize = 256;
const MAX_REFERENCE_MEMBERS: usize = 256;
const MAX_REFERENCE_INVITES: usize = 256;
const MAX_REFERENCE_NAME_BYTES: usize = 64;
const MAX_REFERENCE_MONITORS: usize = 100;

/// Every post-registration command family in the frozen client registry.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ReferenceCommandKind {
    /// NICK.
    Nick,
    /// QUIT.
    Quit,
    /// JOIN.
    Join,
    /// PART.
    Part,
    /// MODE.
    Mode,
    /// TOPIC.
    Topic,
    /// NAMES.
    Names,
    /// LIST.
    List,
    /// INVITE.
    Invite,
    /// KICK.
    Kick,
    /// PRIVMSG.
    Privmsg,
    /// NOTICE.
    Notice,
    /// TAGMSG.
    Tagmsg,
    /// MOTD.
    Motd,
    /// LUSERS.
    Lusers,
    /// VERSION.
    Version,
    /// TIME.
    Time,
    /// ADMIN.
    Admin,
    /// INFO.
    Info,
    /// LINKS.
    Links,
    /// WHO.
    Who,
    /// WHOIS.
    Whois,
    /// WHOWAS.
    Whowas,
    /// AWAY.
    Away,
    /// ISON.
    Ison,
    /// USERHOST.
    Userhost,
    /// MONITOR.
    Monitor,
    /// SETNAME.
    Setname,
    /// ACCT.
    Acct,
    /// CHANCTL.
    Chanctl,
    /// CHATHISTORY.
    Chathistory,
}

/// Frozen command coverage vector used to prove registry completeness.
pub const ALL_REFERENCE_COMMAND_KINDS: &[ReferenceCommandKind] = &[
    ReferenceCommandKind::Nick,
    ReferenceCommandKind::Quit,
    ReferenceCommandKind::Join,
    ReferenceCommandKind::Part,
    ReferenceCommandKind::Mode,
    ReferenceCommandKind::Topic,
    ReferenceCommandKind::Names,
    ReferenceCommandKind::List,
    ReferenceCommandKind::Invite,
    ReferenceCommandKind::Kick,
    ReferenceCommandKind::Privmsg,
    ReferenceCommandKind::Notice,
    ReferenceCommandKind::Tagmsg,
    ReferenceCommandKind::Motd,
    ReferenceCommandKind::Lusers,
    ReferenceCommandKind::Version,
    ReferenceCommandKind::Time,
    ReferenceCommandKind::Admin,
    ReferenceCommandKind::Info,
    ReferenceCommandKind::Links,
    ReferenceCommandKind::Who,
    ReferenceCommandKind::Whois,
    ReferenceCommandKind::Whowas,
    ReferenceCommandKind::Away,
    ReferenceCommandKind::Ison,
    ReferenceCommandKind::Userhost,
    ReferenceCommandKind::Monitor,
    ReferenceCommandKind::Setname,
    ReferenceCommandKind::Acct,
    ReferenceCommandKind::Chanctl,
    ReferenceCommandKind::Chathistory,
];

impl ReferenceCommandKind {
    /// Maps an exact frozen registry spelling into the independent command set.
    pub fn from_registered_name(name: &str) -> Result<Self, ReferenceDomainError> {
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
            _ => Err(ReferenceDomainError::Invalid),
        }
    }
}

/// One message target in the independent reference model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceMessageTarget {
    /// One immutable channel instance.
    Channel(u16),
    /// One live user.
    User(u16),
}

/// One executable post-registration command for the independent model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReferenceCommand {
    /// Change the current nickname.
    Nick {
        /// New canonical nickname.
        nickname: String,
    },
    /// Close the current session.
    Quit,
    /// Join or create one channel.
    Join {
        /// Canonical channel name.
        channel: String,
        /// Immutable channel creation.
        instance: u16,
    },
    /// Leave one channel.
    Part {
        /// Current channel creation.
        instance: u16,
    },
    /// Change one role.
    ModeRole {
        /// Current channel creation.
        instance: u16,
        /// Target live user.
        target: u16,
        /// New highest role.
        role: ReferenceRole,
    },
    /// Change one channel visibility mode.
    ModeVisibility {
        /// Current channel creation.
        instance: u16,
        /// New discovery policy.
        visibility: ReferenceVisibility,
    },
    /// Set one plaintext topic marker.
    TopicSet {
        /// Current channel creation.
        instance: u16,
    },
    /// Execute one read-only command family.
    Query(ReferenceCommandKind),
    /// Create one invitation.
    Invite {
        /// Invited live user.
        target: u16,
        /// Current channel creation.
        instance: u16,
        /// Unique invitation identity.
        invite: u16,
        /// Explicit monotonic expiry tick.
        expires_at: u64,
    },
    /// Remove one lower-role member.
    Kick {
        /// Target lower-role user.
        target: u16,
        /// Current channel creation.
        instance: u16,
    },
    /// Resolve and authorize one message target.
    Message {
        /// PRIVMSG, NOTICE, or TAGMSG.
        kind: ReferenceCommandKind,
        /// Resolved target.
        target: ReferenceMessageTarget,
    },
    /// Set or clear away state.
    Away {
        /// Whether away state is set.
        enabled: bool,
    },
    /// Add one canonical monitor nickname.
    MonitorAdd {
        /// Canonical nickname to add.
        nickname: String,
    },
    /// Remove one canonical monitor nickname.
    MonitorRemove {
        /// Canonical nickname to remove.
        nickname: String,
    },
    /// Clear every monitor nickname.
    MonitorClear,
    /// Change one display-name marker.
    Setname {
        /// New bounded display-name marker.
        display_name: String,
    },
    /// Apply one authenticated account setting.
    AccountUpdate,
    /// Register or unregister one owned channel.
    ChannelRegistration {
        /// Current channel creation.
        instance: u16,
        /// Whether the channel remains registered at zero membership.
        registered: bool,
    },
    /// Read history from one registered current membership.
    Chathistory {
        /// Registered current channel membership.
        instance: u16,
    },
}

impl ReferenceCommand {
    /// Returns the frozen command family exercised by this operation.
    #[must_use]
    pub const fn kind(&self) -> ReferenceCommandKind {
        match self {
            Self::Nick { .. } => ReferenceCommandKind::Nick,
            Self::Quit => ReferenceCommandKind::Quit,
            Self::Join { .. } => ReferenceCommandKind::Join,
            Self::Part { .. } => ReferenceCommandKind::Part,
            Self::ModeRole { .. } | Self::ModeVisibility { .. } => ReferenceCommandKind::Mode,
            Self::TopicSet { .. } => ReferenceCommandKind::Topic,
            Self::Query(kind) => *kind,
            Self::Invite { .. } => ReferenceCommandKind::Invite,
            Self::Kick { .. } => ReferenceCommandKind::Kick,
            Self::Message { kind, .. } => *kind,
            Self::Away { .. } => ReferenceCommandKind::Away,
            Self::MonitorAdd { .. } | Self::MonitorRemove { .. } | Self::MonitorClear => {
                ReferenceCommandKind::Monitor
            }
            Self::Setname { .. } => ReferenceCommandKind::Setname,
            Self::AccountUpdate => ReferenceCommandKind::Acct,
            Self::ChannelRegistration { .. } => ReferenceCommandKind::Chanctl,
            Self::Chathistory { .. } => ReferenceCommandKind::Chathistory,
        }
    }
}

/// Reference authorization role in strict ascending order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ReferenceRole {
    /// Ordinary membership.
    Member,
    /// Moderated-channel speaking authority.
    Voice,
    /// Topic and routine moderation authority.
    HalfOperator,
    /// Mode and role-grant authority.
    Operator,
    /// Policy administration authority.
    Administrator,
    /// Channel ownership authority.
    Owner,
}

/// Reference discovery policy with mutually exclusive values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceVisibility {
    /// Public directory entry.
    Listed,
    /// Exact lookup only.
    Unlisted,
    /// Existence hidden from outsiders.
    Secret,
}

/// One independently modeled state-machine input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReferenceDomainStep {
    /// Introduce one immutable account and initial session-generation fence.
    CreateAccount {
        /// Immutable account identity.
        account: u16,
        /// Initial account-session generation.
        generation: u64,
    },
    /// Introduce one session with distinct session, user, nickname, and cloak identities.
    OpenSession {
        /// Physical-session identity.
        session: u16,
        /// Per-connection user identity.
        user: u16,
        /// Optional immutable account authority.
        account: Option<u16>,
        /// Account-generation proof captured at authentication.
        account_generation: u64,
        /// Per-session stale-completion fence.
        session_generation: u64,
        /// Canonical routing nickname.
        nickname: String,
        /// Independent public-cloak canary.
        cloak: u32,
    },
    /// Replace one session's authority using an explicit generation fence.
    SwitchAccount {
        /// Live user whose authority changes.
        user: u16,
        /// New account authority or guest state.
        account: Option<u16>,
        /// Required current session generation.
        expected_session_generation: u64,
        /// Generation of the new account authority.
        account_generation: u64,
    },
    /// Change one routing nickname without changing User ID.
    Rename {
        /// Live user retaining its identity.
        user: u16,
        /// New unique canonical nickname.
        nickname: String,
    },
    /// Close one session and all its memberships.
    CloseSession {
        /// Live user being removed.
        user: u16,
    },
    /// Join or create one channel instance.
    Join {
        /// Joining live user.
        user: u16,
        /// Canonical channel name.
        channel: String,
        /// Immutable creation identity.
        instance: u16,
    },
    /// Leave one current channel instance.
    Part {
        /// Departing live user.
        user: u16,
        /// Current channel creation.
        instance: u16,
    },
    /// Apply one role transition checked against current authority.
    SetRole {
        /// Authorizing member.
        actor: u16,
        /// Member whose role changes.
        target: u16,
        /// Current channel creation.
        instance: u16,
        /// New highest role.
        role: ReferenceRole,
    },
    /// Replace the exclusive channel visibility value.
    SetVisibility {
        /// Authorizing member.
        actor: u16,
        /// Current channel creation.
        instance: u16,
        /// New exclusive discovery policy.
        visibility: ReferenceVisibility,
    },
    /// Create a unique, revision-bound invitation.
    Invite {
        /// Authorizing member.
        actor: u16,
        /// Invited live user.
        target: u16,
        /// Current channel creation.
        instance: u16,
        /// Unique invitation identity.
        invite: u16,
        /// Explicit process-local expiry tick.
        expires_at: u64,
    },
    /// Delete an account and every session currently carrying its authority.
    DeleteAccount {
        /// Immutable account being deleted.
        account: u16,
        /// Required current account generation.
        expected_generation: u64,
    },
    /// Apply a coordinator sequence, rejecting duplicates and gaps.
    FederationApply {
        /// Immutable federation origin.
        origin: u16,
        /// Next contiguous operation sequence.
        sequence: u64,
    },
    /// Exercise one frozen command-registry arm against a live user.
    ExecuteCommand {
        /// Live user executing the arm.
        user: u16,
        /// Executable command operation.
        command: ReferenceCommand,
    },
}

/// Closed rejection classes for the independent model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceDomainError {
    /// An identity, name, membership, or invite already exists.
    Duplicate,
    /// A referenced value does not exist.
    NotFound,
    /// A supplied generation or sequence is stale.
    Stale,
    /// A federation input skipped a required sequence.
    Gap,
    /// Current authority is insufficient.
    Forbidden,
    /// A fixed test-model limit was reached.
    LimitExceeded,
    /// An input is malformed or violates a state precondition.
    Invalid,
    /// Checked revision arithmetic overflowed.
    Overflow,
    /// An internal reference invariant failed.
    InvariantViolation,
}

impl fmt::Display for ReferenceDomainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Duplicate => "reference identity is duplicated",
            Self::NotFound => "reference target was not found",
            Self::Stale => "reference input is stale",
            Self::Gap => "reference sequence has a gap",
            Self::Forbidden => "reference action is forbidden",
            Self::LimitExceeded => "reference limit was exceeded",
            Self::Invalid => "reference input is invalid",
            Self::Overflow => "reference arithmetic overflowed",
            Self::InvariantViolation => "reference invariant failed",
        };
        formatter.write_str(message)
    }
}

impl Error for ReferenceDomainError {}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReferenceAccount {
    generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReferenceSession {
    session: u16,
    account: Option<u16>,
    account_generation: u64,
    session_generation: u64,
    nickname: String,
    cloak: u32,
    channels: BTreeSet<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReferenceChannel {
    name: String,
    members: BTreeMap<u16, ReferenceRole>,
    visibility: ReferenceVisibility,
    invites: BTreeMap<u16, (u16, u64, u64)>,
}

/// Stable public session snapshot for implementation comparisons.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceSessionSnapshot {
    /// User identity used as the snapshot key.
    pub user: u16,
    /// Physical session identity.
    pub session: u16,
    /// Optional account authority.
    pub account: Option<u16>,
    /// Current session generation.
    pub generation: u64,
    /// Current routing nickname.
    pub nickname: String,
    /// Independently supplied public cloak canary.
    pub cloak: u32,
    /// Joined immutable channel instances.
    pub channels: Vec<u16>,
}

/// Stable public channel snapshot for implementation comparisons.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceChannelSnapshot {
    /// Immutable channel-creation identity.
    pub instance: u16,
    /// Canonical channel name.
    pub name: String,
    /// Exclusive discovery value.
    pub visibility: ReferenceVisibility,
    /// Members and roles in User-ID order.
    pub members: Vec<(u16, ReferenceRole)>,
    /// Invitation identities in order.
    pub invites: Vec<u16>,
}

/// Deterministic full snapshot of independent reference state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceDomainSnapshot {
    /// State revision advanced only by accepted mutating steps.
    pub revision: u64,
    /// Account identities and generation fences.
    pub accounts: Vec<(u16, u64)>,
    /// Session snapshots in User-ID order.
    pub sessions: Vec<ReferenceSessionSnapshot>,
    /// Channel snapshots in instance-ID order.
    pub channels: Vec<ReferenceChannelSnapshot>,
    /// Highest contiguous sequence per federation origin.
    pub federation_sequences: Vec<(u16, u64)>,
    /// Users currently marked away.
    pub away_users: Vec<u16>,
    /// Canonical monitor sets in User-ID order.
    pub monitors: Vec<(u16, Vec<String>)>,
    /// Current display-name markers in User-ID order.
    pub display_names: Vec<(u16, String)>,
    /// Accepted account-setting counts in Account-ID order.
    pub account_updates: Vec<(u16, u64)>,
    /// Channel instances with a plaintext topic marker.
    pub topics: Vec<u16>,
    /// Registered channel instances.
    pub registered_channels: Vec<u16>,
    /// Command families exercised so far.
    pub observed_commands: Vec<ReferenceCommandKind>,
}

/// Independent copy-on-accept reference state machine.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReferenceDomainModel {
    revision: u64,
    accounts: BTreeMap<u16, ReferenceAccount>,
    sessions: BTreeMap<u16, ReferenceSession>,
    session_ids: BTreeSet<u16>,
    nicknames: BTreeMap<String, u16>,
    channels: BTreeMap<u16, ReferenceChannel>,
    channel_names: BTreeMap<String, u16>,
    federation_sequences: BTreeMap<u16, u64>,
    away_users: BTreeSet<u16>,
    monitors: BTreeMap<u16, BTreeSet<String>>,
    display_names: BTreeMap<u16, String>,
    account_updates: BTreeMap<u16, u64>,
    topics: BTreeSet<u16>,
    registered_channels: BTreeSet<u16>,
    observed_commands: BTreeSet<ReferenceCommandKind>,
}

impl ReferenceDomainModel {
    /// Creates empty reference state at revision zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            revision: 0,
            accounts: BTreeMap::new(),
            sessions: BTreeMap::new(),
            session_ids: BTreeSet::new(),
            nicknames: BTreeMap::new(),
            channels: BTreeMap::new(),
            channel_names: BTreeMap::new(),
            federation_sequences: BTreeMap::new(),
            away_users: BTreeSet::new(),
            monitors: BTreeMap::new(),
            display_names: BTreeMap::new(),
            account_updates: BTreeMap::new(),
            topics: BTreeSet::new(),
            registered_channels: BTreeSet::new(),
            observed_commands: BTreeSet::new(),
        }
    }

    /// Applies one step atomically and checks all invariants after acceptance.
    pub fn apply(&mut self, step: ReferenceDomainStep) -> Result<(), ReferenceDomainError> {
        let mut next = self.clone();
        let mutating = next.apply_inner(step)?;
        if mutating {
            next.revision = next
                .revision
                .checked_add(1)
                .ok_or(ReferenceDomainError::Overflow)?;
        }
        next.validate()?;
        *self = next;
        Ok(())
    }

    /// Returns a stable snapshot containing no private implementation maps.
    #[must_use]
    pub fn snapshot(&self) -> ReferenceDomainSnapshot {
        ReferenceDomainSnapshot {
            revision: self.revision,
            accounts: self
                .accounts
                .iter()
                .map(|(account, state)| (*account, state.generation))
                .collect(),
            sessions: self.session_snapshots(),
            channels: self.channel_snapshots(),
            federation_sequences: self
                .federation_sequences
                .iter()
                .map(|(origin, sequence)| (*origin, *sequence))
                .collect(),
            away_users: self.away_users.iter().copied().collect(),
            monitors: self
                .monitors
                .iter()
                .map(|(user, nicknames)| (*user, nicknames.iter().cloned().collect()))
                .collect(),
            display_names: self
                .display_names
                .iter()
                .map(|(user, display_name)| (*user, display_name.clone()))
                .collect(),
            account_updates: self
                .account_updates
                .iter()
                .map(|(account, count)| (*account, *count))
                .collect(),
            topics: self.topics.iter().copied().collect(),
            registered_channels: self.registered_channels.iter().copied().collect(),
            observed_commands: self.observed_commands.iter().copied().collect(),
        }
    }

    // agenc-review: focus owner=core reviewed=2026-08-26 reason=closed-reference-step-dispatcher
    fn apply_inner(&mut self, step: ReferenceDomainStep) -> Result<bool, ReferenceDomainError> {
        match step {
            ReferenceDomainStep::CreateAccount {
                account,
                generation,
            } => self.create_account(account, generation),
            ReferenceDomainStep::OpenSession {
                session,
                user,
                account,
                account_generation,
                session_generation,
                nickname,
                cloak,
            } => self.open_session(
                user,
                ReferenceSession {
                    session,
                    account,
                    account_generation,
                    session_generation,
                    nickname,
                    cloak,
                    channels: BTreeSet::new(),
                },
            ),
            ReferenceDomainStep::SwitchAccount {
                user,
                account,
                expected_session_generation,
                account_generation,
            } => self.switch_account(
                user,
                account,
                expected_session_generation,
                account_generation,
            ),
            ReferenceDomainStep::Rename { user, nickname } => self.rename(user, nickname),
            ReferenceDomainStep::CloseSession { user } => self.close_session(user),
            ReferenceDomainStep::Join {
                user,
                channel,
                instance,
            } => self.join(user, channel, instance),
            ReferenceDomainStep::Part { user, instance } => self.part(user, instance),
            ReferenceDomainStep::SetRole {
                actor,
                target,
                instance,
                role,
            } => self.set_role(actor, target, instance, role),
            ReferenceDomainStep::SetVisibility {
                actor,
                instance,
                visibility,
            } => self.set_visibility(actor, instance, visibility),
            ReferenceDomainStep::Invite {
                actor,
                target,
                instance,
                invite,
                expires_at,
            } => self.invite(actor, target, instance, invite, expires_at),
            ReferenceDomainStep::DeleteAccount {
                account,
                expected_generation,
            } => self.delete_account(account, expected_generation),
            ReferenceDomainStep::FederationApply { origin, sequence } => {
                self.federation_apply(origin, sequence)
            }
            ReferenceDomainStep::ExecuteCommand { user, command } => {
                self.execute_command(user, command)
            }
        }
    }

    fn create_account(
        &mut self,
        account: u16,
        generation: u64,
    ) -> Result<bool, ReferenceDomainError> {
        if self.accounts.len() >= MAX_REFERENCE_ACCOUNTS {
            return Err(ReferenceDomainError::LimitExceeded);
        }
        if self
            .accounts
            .insert(account, ReferenceAccount { generation })
            .is_some()
        {
            return Err(ReferenceDomainError::Duplicate);
        }
        Ok(true)
    }

    fn open_session(
        &mut self,
        user: u16,
        session: ReferenceSession,
    ) -> Result<bool, ReferenceDomainError> {
        validate_name(&session.nickname)?;
        if self.sessions.len() >= MAX_REFERENCE_SESSIONS {
            return Err(ReferenceDomainError::LimitExceeded);
        }
        if self.sessions.contains_key(&user)
            || self.session_ids.contains(&session.session)
            || self.nicknames.contains_key(&session.nickname)
        {
            return Err(ReferenceDomainError::Duplicate);
        }
        validate_account_fence(&self.accounts, session.account, session.account_generation)?;
        self.session_ids.insert(session.session);
        self.nicknames.insert(session.nickname.clone(), user);
        self.sessions.insert(user, session);
        Ok(true)
    }

    fn switch_account(
        &mut self,
        user: u16,
        account: Option<u16>,
        expected_session_generation: u64,
        account_generation: u64,
    ) -> Result<bool, ReferenceDomainError> {
        validate_account_fence(&self.accounts, account, account_generation)?;
        let session = self
            .sessions
            .get_mut(&user)
            .ok_or(ReferenceDomainError::NotFound)?;
        if session.session_generation != expected_session_generation {
            return Err(ReferenceDomainError::Stale);
        }
        let was_guest = session.account.is_none();
        session.account = account;
        session.account_generation = account_generation;
        session.session_generation = session
            .session_generation
            .checked_add(1)
            .ok_or(ReferenceDomainError::Overflow)?;
        if was_guest && account.is_some() {
            for channel in self.channels.values_mut() {
                channel.invites.retain(|_, (target, _, _)| *target != user);
            }
        }
        Ok(true)
    }

    fn rename(&mut self, user: u16, nickname: String) -> Result<bool, ReferenceDomainError> {
        validate_name(&nickname)?;
        if self.nicknames.contains_key(&nickname) {
            return Err(ReferenceDomainError::Duplicate);
        }
        let session = self
            .sessions
            .get_mut(&user)
            .ok_or(ReferenceDomainError::NotFound)?;
        self.nicknames.remove(&session.nickname);
        self.nicknames.insert(nickname.clone(), user);
        session.nickname = nickname;
        Ok(true)
    }

    fn close_session(&mut self, user: u16) -> Result<bool, ReferenceDomainError> {
        let session = self
            .sessions
            .remove(&user)
            .ok_or(ReferenceDomainError::NotFound)?;
        self.session_ids.remove(&session.session);
        self.nicknames.remove(&session.nickname);
        self.away_users.remove(&user);
        self.monitors.remove(&user);
        self.display_names.remove(&user);
        for channel in self.channels.values_mut() {
            channel.invites.retain(|_, (target, _, _)| *target != user);
        }
        for instance in session.channels {
            self.part_membership(user, instance);
        }
        Ok(true)
    }

    fn join(
        &mut self,
        user: u16,
        channel: String,
        instance: u16,
    ) -> Result<bool, ReferenceDomainError> {
        validate_name(&channel)?;
        if !self.sessions.contains_key(&user) {
            return Err(ReferenceDomainError::NotFound);
        }
        let role = if let Some(current) = self.channel_names.get(&channel) {
            if *current != instance {
                return Err(ReferenceDomainError::Stale);
            }
            ReferenceRole::Member
        } else {
            self.insert_channel(user, channel, instance)?;
            ReferenceRole::Owner
        };
        let target = self
            .channels
            .get_mut(&instance)
            .ok_or(ReferenceDomainError::NotFound)?;
        if target.members.len() >= MAX_REFERENCE_MEMBERS {
            return Err(ReferenceDomainError::LimitExceeded);
        }
        if target.members.contains_key(&user) {
            return Err(ReferenceDomainError::Duplicate);
        }
        target.members.insert(user, role);
        let session = self
            .sessions
            .get_mut(&user)
            .ok_or(ReferenceDomainError::InvariantViolation)?;
        session.channels.insert(instance);
        Ok(true)
    }

    fn insert_channel(
        &mut self,
        creator: u16,
        channel: String,
        instance: u16,
    ) -> Result<(), ReferenceDomainError> {
        if self.channels.len() >= MAX_REFERENCE_CHANNELS || self.channels.contains_key(&instance) {
            return Err(ReferenceDomainError::LimitExceeded);
        }
        self.channel_names.insert(channel.clone(), instance);
        self.channels.insert(
            instance,
            ReferenceChannel {
                name: channel,
                members: BTreeMap::new(),
                visibility: ReferenceVisibility::Listed,
                invites: BTreeMap::new(),
            },
        );
        if !self.sessions.contains_key(&creator) {
            return Err(ReferenceDomainError::InvariantViolation);
        }
        Ok(())
    }

    fn part(&mut self, user: u16, instance: u16) -> Result<bool, ReferenceDomainError> {
        let channel = self
            .channels
            .get(&instance)
            .ok_or(ReferenceDomainError::NotFound)?;
        if !channel.members.contains_key(&user) {
            return Err(ReferenceDomainError::NotFound);
        }
        self.part_membership(user, instance);
        Ok(true)
    }

    fn part_membership(&mut self, user: u16, instance: u16) {
        if let Some(session) = self.sessions.get_mut(&user) {
            session.channels.remove(&instance);
        }
        let registered = self.registered_channels.contains(&instance);
        let destroy = self.channels.get_mut(&instance).is_some_and(|channel| {
            channel.members.remove(&user);
            channel.members.is_empty() && !registered
        });
        if destroy && let Some(channel) = self.channels.remove(&instance) {
            self.channel_names.remove(&channel.name);
            self.topics.remove(&instance);
            self.registered_channels.remove(&instance);
        }
    }

    fn set_role(
        &mut self,
        actor: u16,
        target: u16,
        instance: u16,
        role: ReferenceRole,
    ) -> Result<bool, ReferenceDomainError> {
        let channel = self
            .channels
            .get_mut(&instance)
            .ok_or(ReferenceDomainError::NotFound)?;
        let actor_role = channel
            .members
            .get(&actor)
            .copied()
            .ok_or(ReferenceDomainError::Forbidden)?;
        let target_role = channel
            .members
            .get(&target)
            .copied()
            .ok_or(ReferenceDomainError::NotFound)?;
        if actor_role < ReferenceRole::Operator || actor_role < role || target_role >= actor_role {
            return Err(ReferenceDomainError::Forbidden);
        }
        channel.members.insert(target, role);
        Ok(true)
    }

    fn set_visibility(
        &mut self,
        actor: u16,
        instance: u16,
        visibility: ReferenceVisibility,
    ) -> Result<bool, ReferenceDomainError> {
        let channel = self
            .channels
            .get_mut(&instance)
            .ok_or(ReferenceDomainError::NotFound)?;
        if channel.members.get(&actor).copied() < Some(ReferenceRole::Operator) {
            return Err(ReferenceDomainError::Forbidden);
        }
        channel.visibility = visibility;
        Ok(true)
    }

    fn invite(
        &mut self,
        actor: u16,
        target: u16,
        instance: u16,
        invite: u16,
        expires_at: u64,
    ) -> Result<bool, ReferenceDomainError> {
        if !self.sessions.contains_key(&target) {
            return Err(ReferenceDomainError::NotFound);
        }
        let channel = self
            .channels
            .get_mut(&instance)
            .ok_or(ReferenceDomainError::NotFound)?;
        if channel.members.get(&actor).copied() < Some(ReferenceRole::Operator) {
            return Err(ReferenceDomainError::Forbidden);
        }
        if channel.invites.len() >= MAX_REFERENCE_INVITES {
            return Err(ReferenceDomainError::LimitExceeded);
        }
        if channel
            .invites
            .insert(invite, (target, self.revision, expires_at))
            .is_some()
        {
            return Err(ReferenceDomainError::Duplicate);
        }
        Ok(true)
    }

    fn delete_account(
        &mut self,
        account: u16,
        expected_generation: u64,
    ) -> Result<bool, ReferenceDomainError> {
        let state = self
            .accounts
            .get(&account)
            .ok_or(ReferenceDomainError::NotFound)?;
        if state.generation != expected_generation {
            return Err(ReferenceDomainError::Stale);
        }
        let users: Vec<u16> = self
            .sessions
            .iter()
            .filter_map(|(user, session)| (session.account == Some(account)).then_some(*user))
            .collect();
        for user in users {
            self.close_session(user)?;
        }
        self.accounts.remove(&account);
        self.account_updates.remove(&account);
        Ok(true)
    }

    fn federation_apply(
        &mut self,
        origin: u16,
        sequence: u64,
    ) -> Result<bool, ReferenceDomainError> {
        let current = self.federation_sequences.get(&origin).copied().unwrap_or(0);
        let expected = current
            .checked_add(1)
            .ok_or(ReferenceDomainError::Overflow)?;
        if sequence < expected {
            return Err(ReferenceDomainError::Stale);
        }
        if sequence > expected {
            return Err(ReferenceDomainError::Gap);
        }
        self.federation_sequences.insert(origin, sequence);
        Ok(true)
    }

    fn execute_command(
        &mut self,
        user: u16,
        command: ReferenceCommand,
    ) -> Result<bool, ReferenceDomainError> {
        if !self.sessions.contains_key(&user) {
            return Err(ReferenceDomainError::NotFound);
        }
        let kind = command.kind();
        let mutating = match command {
            ReferenceCommand::Nick { nickname } => self.rename(user, nickname)?,
            ReferenceCommand::Quit => self.close_session(user)?,
            ReferenceCommand::Join { channel, instance } => self.join(user, channel, instance)?,
            ReferenceCommand::Part { instance } => self.part(user, instance)?,
            ReferenceCommand::ModeRole {
                instance,
                target,
                role,
            } => self.set_role(user, target, instance, role)?,
            ReferenceCommand::ModeVisibility {
                instance,
                visibility,
            } => self.set_visibility(user, instance, visibility)?,
            ReferenceCommand::TopicSet { instance } => self.set_topic(user, instance)?,
            ReferenceCommand::Query(query) => self.execute_query(query)?,
            ReferenceCommand::Invite {
                target,
                instance,
                invite,
                expires_at,
            } => self.invite(user, target, instance, invite, expires_at)?,
            ReferenceCommand::Kick { target, instance } => self.kick(user, target, instance)?,
            ReferenceCommand::Message {
                kind: message_kind,
                target,
            } => self.route_message(user, message_kind, target)?,
            ReferenceCommand::Away { enabled } => self.set_away(user, enabled),
            ReferenceCommand::MonitorAdd { nickname } => self.monitor_add(user, nickname)?,
            ReferenceCommand::MonitorRemove { nickname } => self.monitor_remove(user, &nickname),
            ReferenceCommand::MonitorClear => self.monitor_clear(user),
            ReferenceCommand::Setname { display_name } => {
                self.set_display_name(user, display_name)?
            }
            ReferenceCommand::AccountUpdate => self.update_account(user)?,
            ReferenceCommand::ChannelRegistration {
                instance,
                registered,
            } => self.set_channel_registration(user, instance, registered)?,
            ReferenceCommand::Chathistory { instance } => self.read_history(user, instance)?,
        };
        self.observed_commands.insert(kind);
        Ok(mutating)
    }

    fn execute_query(&self, kind: ReferenceCommandKind) -> Result<bool, ReferenceDomainError> {
        if matches!(
            kind,
            ReferenceCommandKind::Names
                | ReferenceCommandKind::List
                | ReferenceCommandKind::Motd
                | ReferenceCommandKind::Lusers
                | ReferenceCommandKind::Version
                | ReferenceCommandKind::Time
                | ReferenceCommandKind::Admin
                | ReferenceCommandKind::Info
                | ReferenceCommandKind::Links
                | ReferenceCommandKind::Who
                | ReferenceCommandKind::Whois
                | ReferenceCommandKind::Whowas
                | ReferenceCommandKind::Ison
                | ReferenceCommandKind::Userhost
        ) {
            return Ok(false);
        }
        Err(ReferenceDomainError::Invalid)
    }

    fn set_topic(&mut self, actor: u16, instance: u16) -> Result<bool, ReferenceDomainError> {
        let channel = self
            .channels
            .get(&instance)
            .ok_or(ReferenceDomainError::NotFound)?;
        if channel.members.get(&actor).copied() < Some(ReferenceRole::HalfOperator) {
            return Err(ReferenceDomainError::Forbidden);
        }
        self.topics.insert(instance);
        Ok(true)
    }

    fn kick(
        &mut self,
        actor: u16,
        target: u16,
        instance: u16,
    ) -> Result<bool, ReferenceDomainError> {
        let channel = self
            .channels
            .get(&instance)
            .ok_or(ReferenceDomainError::NotFound)?;
        let actor_role = channel
            .members
            .get(&actor)
            .copied()
            .ok_or(ReferenceDomainError::Forbidden)?;
        let target_role = channel
            .members
            .get(&target)
            .copied()
            .ok_or(ReferenceDomainError::NotFound)?;
        if actor_role < ReferenceRole::HalfOperator || target_role >= actor_role {
            return Err(ReferenceDomainError::Forbidden);
        }
        self.part_membership(target, instance);
        Ok(true)
    }

    fn route_message(
        &self,
        sender: u16,
        kind: ReferenceCommandKind,
        target: ReferenceMessageTarget,
    ) -> Result<bool, ReferenceDomainError> {
        if !matches!(
            kind,
            ReferenceCommandKind::Privmsg
                | ReferenceCommandKind::Notice
                | ReferenceCommandKind::Tagmsg
        ) {
            return Err(ReferenceDomainError::Invalid);
        }
        match target {
            ReferenceMessageTarget::Channel(instance) => {
                let channel = self
                    .channels
                    .get(&instance)
                    .ok_or(ReferenceDomainError::NotFound)?;
                if !channel.members.contains_key(&sender) {
                    return Err(ReferenceDomainError::Forbidden);
                }
            }
            ReferenceMessageTarget::User(target) => {
                if !self.sessions.contains_key(&target) {
                    return Err(ReferenceDomainError::NotFound);
                }
            }
        }
        Ok(false)
    }

    fn set_away(&mut self, user: u16, enabled: bool) -> bool {
        if enabled {
            self.away_users.insert(user);
        } else {
            self.away_users.remove(&user);
        }
        true
    }

    fn monitor_add(&mut self, user: u16, nickname: String) -> Result<bool, ReferenceDomainError> {
        validate_name(&nickname)?;
        let targets = self.monitors.entry(user).or_default();
        if !targets.contains(&nickname) && targets.len() >= MAX_REFERENCE_MONITORS {
            return Err(ReferenceDomainError::LimitExceeded);
        }
        targets.insert(nickname);
        Ok(true)
    }

    fn monitor_remove(&mut self, user: u16, nickname: &str) -> bool {
        if let Some(targets) = self.monitors.get_mut(&user) {
            targets.remove(nickname);
        }
        true
    }

    fn monitor_clear(&mut self, user: u16) -> bool {
        self.monitors.remove(&user);
        true
    }

    fn set_display_name(
        &mut self,
        user: u16,
        display_name: String,
    ) -> Result<bool, ReferenceDomainError> {
        validate_name(&display_name)?;
        self.display_names.insert(user, display_name);
        Ok(true)
    }

    fn update_account(&mut self, user: u16) -> Result<bool, ReferenceDomainError> {
        let account = self
            .sessions
            .get(&user)
            .and_then(|session| session.account)
            .ok_or(ReferenceDomainError::Forbidden)?;
        let count = self.account_updates.entry(account).or_default();
        *count = count.checked_add(1).ok_or(ReferenceDomainError::Overflow)?;
        Ok(true)
    }

    fn set_channel_registration(
        &mut self,
        actor: u16,
        instance: u16,
        registered: bool,
    ) -> Result<bool, ReferenceDomainError> {
        let channel = self
            .channels
            .get(&instance)
            .ok_or(ReferenceDomainError::NotFound)?;
        if channel.members.get(&actor) != Some(&ReferenceRole::Owner) {
            return Err(ReferenceDomainError::Forbidden);
        }
        if registered {
            self.registered_channels.insert(instance);
        } else {
            self.registered_channels.remove(&instance);
        }
        Ok(true)
    }

    fn read_history(&self, user: u16, instance: u16) -> Result<bool, ReferenceDomainError> {
        let channel = self
            .channels
            .get(&instance)
            .ok_or(ReferenceDomainError::NotFound)?;
        if !channel.members.contains_key(&user) {
            return Err(ReferenceDomainError::Forbidden);
        }
        if !self.registered_channels.contains(&instance) {
            return Err(ReferenceDomainError::Invalid);
        }
        Ok(false)
    }

    fn validate(&self) -> Result<(), ReferenceDomainError> {
        if self.sessions.len() != self.session_ids.len()
            || self.sessions.len() != self.nicknames.len()
            || self.channels.len() != self.channel_names.len()
        {
            return Err(ReferenceDomainError::InvariantViolation);
        }
        self.validate_sessions()?;
        self.validate_channels()?;
        self.validate_command_state()
    }

    fn validate_sessions(&self) -> Result<(), ReferenceDomainError> {
        for (user, session) in &self.sessions {
            if !self.session_ids.contains(&session.session)
                || self.nicknames.get(&session.nickname) != Some(user)
            {
                return Err(ReferenceDomainError::InvariantViolation);
            }
            validate_account_fence(&self.accounts, session.account, session.account_generation)?;
            for instance in &session.channels {
                if !self
                    .channels
                    .get(instance)
                    .is_some_and(|channel| channel.members.contains_key(user))
                {
                    return Err(ReferenceDomainError::InvariantViolation);
                }
            }
        }
        Ok(())
    }

    fn validate_channels(&self) -> Result<(), ReferenceDomainError> {
        for (instance, channel) in &self.channels {
            if self.channel_names.get(&channel.name) != Some(instance) {
                return Err(ReferenceDomainError::InvariantViolation);
            }
            for user in channel.members.keys() {
                if !self
                    .sessions
                    .get(user)
                    .is_some_and(|session| session.channels.contains(instance))
                {
                    return Err(ReferenceDomainError::InvariantViolation);
                }
            }
        }
        Ok(())
    }

    fn validate_command_state(&self) -> Result<(), ReferenceDomainError> {
        if self
            .away_users
            .iter()
            .chain(self.monitors.keys())
            .chain(self.display_names.keys())
            .any(|user| !self.sessions.contains_key(user))
        {
            return Err(ReferenceDomainError::InvariantViolation);
        }
        if self.monitors.values().any(|targets| {
            targets.len() > MAX_REFERENCE_MONITORS
                || targets
                    .iter()
                    .any(|nickname| validate_name(nickname).is_err())
        }) {
            return Err(ReferenceDomainError::InvariantViolation);
        }
        if self
            .account_updates
            .keys()
            .any(|account| !self.accounts.contains_key(account))
            || self
                .topics
                .iter()
                .chain(&self.registered_channels)
                .any(|instance| !self.channels.contains_key(instance))
        {
            return Err(ReferenceDomainError::InvariantViolation);
        }
        Ok(())
    }

    fn session_snapshots(&self) -> Vec<ReferenceSessionSnapshot> {
        self.sessions
            .iter()
            .map(|(user, session)| ReferenceSessionSnapshot {
                user: *user,
                session: session.session,
                account: session.account,
                generation: session.session_generation,
                nickname: session.nickname.clone(),
                cloak: session.cloak,
                channels: session.channels.iter().copied().collect(),
            })
            .collect()
    }

    fn channel_snapshots(&self) -> Vec<ReferenceChannelSnapshot> {
        self.channels
            .iter()
            .map(|(instance, channel)| ReferenceChannelSnapshot {
                instance: *instance,
                name: channel.name.clone(),
                visibility: channel.visibility,
                members: channel
                    .members
                    .iter()
                    .map(|(user, role)| (*user, *role))
                    .collect(),
                invites: channel.invites.keys().copied().collect(),
            })
            .collect()
    }
}

fn validate_name(name: &str) -> Result<(), ReferenceDomainError> {
    if name.is_empty() || name.len() > MAX_REFERENCE_NAME_BYTES || !name.is_ascii() {
        return Err(ReferenceDomainError::Invalid);
    }
    Ok(())
}

fn validate_account_fence(
    accounts: &BTreeMap<u16, ReferenceAccount>,
    account: Option<u16>,
    generation: u64,
) -> Result<(), ReferenceDomainError> {
    let Some(account) = account else {
        return Ok(());
    };
    let state = accounts
        .get(&account)
        .ok_or(ReferenceDomainError::NotFound)?;
    if state.generation != generation {
        return Err(ReferenceDomainError::Stale);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(user: u16, session: u16, nickname: &str) -> ReferenceDomainStep {
        ReferenceDomainStep::OpenSession {
            session,
            user,
            account: None,
            account_generation: 0,
            session_generation: 1,
            nickname: nickname.to_owned(),
            cloak: u32::from(user),
        }
    }

    fn joined_model() -> Result<ReferenceDomainModel, ReferenceDomainError> {
        let mut model = ReferenceDomainModel::new();
        model.apply(open(1, 11, "owner"))?;
        model.apply(open(2, 12, "member"))?;
        model.apply(open(3, 13, "outsider"))?;
        model.apply(ReferenceDomainStep::Join {
            user: 1,
            channel: "#reference".to_owned(),
            instance: 20,
        })?;
        model.apply(ReferenceDomainStep::Join {
            user: 2,
            channel: "#reference".to_owned(),
            instance: 20,
        })?;
        Ok(model)
    }

    fn assert_command_rejected_unchanged(
        model: &mut ReferenceDomainModel,
        user: u16,
        command: ReferenceCommand,
        expected: ReferenceDomainError,
    ) {
        let snapshot = model.snapshot();
        assert_eq!(
            model.apply(ReferenceDomainStep::ExecuteCommand { user, command }),
            Err(expected)
        );
        assert_eq!(model.snapshot(), snapshot);
    }

    #[test]
    fn executable_command_guards_reject_without_partial_state() -> Result<(), ReferenceDomainError>
    {
        let mut model = joined_model()?;
        assert_command_rejected_unchanged(
            &mut model,
            2,
            ReferenceCommand::ModeVisibility {
                instance: 20,
                visibility: ReferenceVisibility::Secret,
            },
            ReferenceDomainError::Forbidden,
        );
        assert_command_rejected_unchanged(
            &mut model,
            2,
            ReferenceCommand::ModeRole {
                instance: 20,
                target: 1,
                role: ReferenceRole::Owner,
            },
            ReferenceDomainError::Forbidden,
        );
        assert_command_rejected_unchanged(
            &mut model,
            2,
            ReferenceCommand::TopicSet { instance: 20 },
            ReferenceDomainError::Forbidden,
        );
        assert_command_rejected_unchanged(
            &mut model,
            2,
            ReferenceCommand::Invite {
                target: 3,
                instance: 20,
                invite: 30,
                expires_at: 100,
            },
            ReferenceDomainError::Forbidden,
        );
        assert_command_rejected_unchanged(
            &mut model,
            2,
            ReferenceCommand::Kick {
                target: 1,
                instance: 20,
            },
            ReferenceDomainError::Forbidden,
        );
        assert_command_rejected_unchanged(
            &mut model,
            1,
            ReferenceCommand::Kick {
                target: 3,
                instance: 20,
            },
            ReferenceDomainError::NotFound,
        );
        assert_command_rejected_unchanged(
            &mut model,
            1,
            ReferenceCommand::Message {
                kind: ReferenceCommandKind::Names,
                target: ReferenceMessageTarget::Channel(20),
            },
            ReferenceDomainError::Invalid,
        );
        assert_command_rejected_unchanged(
            &mut model,
            3,
            ReferenceCommand::Message {
                kind: ReferenceCommandKind::Privmsg,
                target: ReferenceMessageTarget::Channel(20),
            },
            ReferenceDomainError::Forbidden,
        );
        assert_command_rejected_unchanged(
            &mut model,
            1,
            ReferenceCommand::Message {
                kind: ReferenceCommandKind::Privmsg,
                target: ReferenceMessageTarget::User(99),
            },
            ReferenceDomainError::NotFound,
        );
        assert_command_rejected_unchanged(
            &mut model,
            2,
            ReferenceCommand::AccountUpdate,
            ReferenceDomainError::Forbidden,
        );
        assert_command_rejected_unchanged(
            &mut model,
            1,
            ReferenceCommand::Setname {
                display_name: "é".to_owned(),
            },
            ReferenceDomainError::Invalid,
        );
        assert_command_rejected_unchanged(
            &mut model,
            2,
            ReferenceCommand::ChannelRegistration {
                instance: 20,
                registered: true,
            },
            ReferenceDomainError::Forbidden,
        );
        assert_command_rejected_unchanged(
            &mut model,
            1,
            ReferenceCommand::Chathistory { instance: 20 },
            ReferenceDomainError::Invalid,
        );
        assert_command_rejected_unchanged(
            &mut model,
            3,
            ReferenceCommand::Chathistory { instance: 20 },
            ReferenceDomainError::Forbidden,
        );
        assert_command_rejected_unchanged(
            &mut model,
            1,
            ReferenceCommand::Query(ReferenceCommandKind::Privmsg),
            ReferenceDomainError::Invalid,
        );

        model.apply(ReferenceDomainStep::ExecuteCommand {
            user: 1,
            command: ReferenceCommand::Away { enabled: false },
        })?;
        model.apply(ReferenceDomainStep::ExecuteCommand {
            user: 3,
            command: ReferenceCommand::MonitorRemove {
                nickname: "nobody".to_owned(),
            },
        })?;
        model.apply(ReferenceDomainStep::ExecuteCommand {
            user: 1,
            command: ReferenceCommand::ChannelRegistration {
                instance: 20,
                registered: true,
            },
        })?;
        model.apply(ReferenceDomainStep::ExecuteCommand {
            user: 1,
            command: ReferenceCommand::Chathistory { instance: 20 },
        })?;
        model.apply(ReferenceDomainStep::ExecuteCommand {
            user: 1,
            command: ReferenceCommand::ChannelRegistration {
                instance: 20,
                registered: false,
            },
        })?;

        let monitors = (0..MAX_REFERENCE_MONITORS)
            .map(|index| format!("monitor{index}"))
            .collect();
        model.monitors.insert(1, monitors);
        model.apply(ReferenceDomainStep::ExecuteCommand {
            user: 1,
            command: ReferenceCommand::MonitorAdd {
                nickname: "monitor0".to_owned(),
            },
        })?;
        assert_command_rejected_unchanged(
            &mut model,
            1,
            ReferenceCommand::MonitorAdd {
                nickname: "monitor-overflow".to_owned(),
            },
            ReferenceDomainError::LimitExceeded,
        );
        Ok(())
    }

    #[test]
    fn reference_rejections_cover_identity_membership_role_and_sequence_edges()
    -> Result<(), ReferenceDomainError> {
        let mut model = ReferenceDomainModel::new();
        model.apply(ReferenceDomainStep::CreateAccount {
            account: 1,
            generation: 7,
        })?;
        assert_eq!(
            model.apply(ReferenceDomainStep::CreateAccount {
                account: 1,
                generation: 7,
            }),
            Err(ReferenceDomainError::Duplicate)
        );
        assert_eq!(
            model.apply(open(1, 11, "")),
            Err(ReferenceDomainError::Invalid)
        );
        assert_eq!(
            model.apply(ReferenceDomainStep::OpenSession {
                session: 11,
                user: 1,
                account: Some(99),
                account_generation: 1,
                session_generation: 1,
                nickname: "missing-account".to_owned(),
                cloak: 1,
            }),
            Err(ReferenceDomainError::NotFound)
        );
        assert_eq!(
            model.apply(ReferenceDomainStep::OpenSession {
                session: 11,
                user: 1,
                account: Some(1),
                account_generation: 6,
                session_generation: 1,
                nickname: "stale-account".to_owned(),
                cloak: 1,
            }),
            Err(ReferenceDomainError::Stale)
        );
        model.apply(open(1, 11, "alpha"))?;
        assert_eq!(
            model.apply(open(1, 12, "beta")),
            Err(ReferenceDomainError::Duplicate)
        );
        assert_eq!(
            model.apply(open(2, 11, "beta")),
            Err(ReferenceDomainError::Duplicate)
        );
        assert_eq!(
            model.apply(open(2, 12, "alpha")),
            Err(ReferenceDomainError::Duplicate)
        );
        assert_eq!(
            model.apply(ReferenceDomainStep::SwitchAccount {
                user: 99,
                account: None,
                expected_session_generation: 1,
                account_generation: 0,
            }),
            Err(ReferenceDomainError::NotFound)
        );
        assert_eq!(
            model.apply(ReferenceDomainStep::SwitchAccount {
                user: 1,
                account: None,
                expected_session_generation: 2,
                account_generation: 0,
            }),
            Err(ReferenceDomainError::Stale)
        );
        assert_eq!(
            model.apply(ReferenceDomainStep::Rename {
                user: 99,
                nickname: "unused".to_owned(),
            }),
            Err(ReferenceDomainError::NotFound)
        );
        assert_eq!(
            model.apply(ReferenceDomainStep::Rename {
                user: 1,
                nickname: "é".to_owned(),
            }),
            Err(ReferenceDomainError::Invalid)
        );
        model.apply(open(2, 12, "beta"))?;
        assert_eq!(
            model.apply(ReferenceDomainStep::Rename {
                user: 1,
                nickname: "beta".to_owned(),
            }),
            Err(ReferenceDomainError::Duplicate)
        );
        assert_eq!(
            model.apply(ReferenceDomainStep::CloseSession { user: 99 }),
            Err(ReferenceDomainError::NotFound)
        );
        assert_eq!(
            model.apply(ReferenceDomainStep::Join {
                user: 99,
                channel: "#missing-user".to_owned(),
                instance: 30,
            }),
            Err(ReferenceDomainError::NotFound)
        );
        model.apply(ReferenceDomainStep::Join {
            user: 1,
            channel: "#one".to_owned(),
            instance: 30,
        })?;
        assert_eq!(
            model.apply(ReferenceDomainStep::Join {
                user: 2,
                channel: "#one".to_owned(),
                instance: 31,
            }),
            Err(ReferenceDomainError::Stale)
        );
        assert_eq!(
            model.apply(ReferenceDomainStep::Join {
                user: 1,
                channel: "#one".to_owned(),
                instance: 30,
            }),
            Err(ReferenceDomainError::Duplicate)
        );
        assert_eq!(
            model.apply(ReferenceDomainStep::Part {
                user: 1,
                instance: 99,
            }),
            Err(ReferenceDomainError::NotFound)
        );
        assert_eq!(
            model.apply(ReferenceDomainStep::Part {
                user: 2,
                instance: 30,
            }),
            Err(ReferenceDomainError::NotFound)
        );
        assert_eq!(
            model.apply(ReferenceDomainStep::ExecuteCommand {
                user: 99,
                command: ReferenceCommand::Query(ReferenceCommandKind::List),
            }),
            Err(ReferenceDomainError::NotFound)
        );
        assert_eq!(
            model.apply(ReferenceDomainStep::DeleteAccount {
                account: 99,
                expected_generation: 1,
            }),
            Err(ReferenceDomainError::NotFound)
        );
        assert_eq!(
            model.apply(ReferenceDomainStep::DeleteAccount {
                account: 1,
                expected_generation: 6,
            }),
            Err(ReferenceDomainError::Stale)
        );
        assert_eq!(
            model.apply(ReferenceDomainStep::FederationApply {
                origin: 1,
                sequence: 2,
            }),
            Err(ReferenceDomainError::Gap)
        );
        model.apply(ReferenceDomainStep::FederationApply {
            origin: 1,
            sequence: 1,
        })?;
        assert_eq!(
            model.apply(ReferenceDomainStep::FederationApply {
                origin: 1,
                sequence: 1,
            }),
            Err(ReferenceDomainError::Stale)
        );
        Ok(())
    }

    #[test]
    fn reference_moderation_invite_and_raw_invariants_fail_closed()
    -> Result<(), ReferenceDomainError> {
        let mut model = joined_model()?;
        assert_eq!(
            model.apply(ReferenceDomainStep::SetRole {
                actor: 3,
                target: 2,
                instance: 20,
                role: ReferenceRole::Voice,
            }),
            Err(ReferenceDomainError::Forbidden)
        );
        assert_eq!(
            model.apply(ReferenceDomainStep::SetRole {
                actor: 1,
                target: 99,
                instance: 20,
                role: ReferenceRole::Voice,
            }),
            Err(ReferenceDomainError::NotFound)
        );
        assert_eq!(
            model.apply(ReferenceDomainStep::SetRole {
                actor: 1,
                target: 2,
                instance: 99,
                role: ReferenceRole::Voice,
            }),
            Err(ReferenceDomainError::NotFound)
        );
        model.apply(ReferenceDomainStep::SetRole {
            actor: 1,
            target: 2,
            instance: 20,
            role: ReferenceRole::Operator,
        })?;
        assert_eq!(
            model.apply(ReferenceDomainStep::SetRole {
                actor: 2,
                target: 1,
                instance: 20,
                role: ReferenceRole::Owner,
            }),
            Err(ReferenceDomainError::Forbidden)
        );
        assert_eq!(
            model.apply(ReferenceDomainStep::SetVisibility {
                actor: 3,
                instance: 20,
                visibility: ReferenceVisibility::Secret,
            }),
            Err(ReferenceDomainError::Forbidden)
        );
        assert_eq!(
            model.apply(ReferenceDomainStep::SetVisibility {
                actor: 1,
                instance: 99,
                visibility: ReferenceVisibility::Secret,
            }),
            Err(ReferenceDomainError::NotFound)
        );
        model.apply(ReferenceDomainStep::SetVisibility {
            actor: 1,
            instance: 20,
            visibility: ReferenceVisibility::Unlisted,
        })?;
        assert_eq!(
            model.apply(ReferenceDomainStep::Invite {
                actor: 1,
                target: 99,
                instance: 20,
                invite: 1,
                expires_at: 100,
            }),
            Err(ReferenceDomainError::NotFound)
        );
        assert_eq!(
            model.apply(ReferenceDomainStep::Invite {
                actor: 1,
                target: 3,
                instance: 99,
                invite: 1,
                expires_at: 100,
            }),
            Err(ReferenceDomainError::NotFound)
        );
        assert_eq!(
            model.apply(ReferenceDomainStep::Invite {
                actor: 3,
                target: 2,
                instance: 20,
                invite: 1,
                expires_at: 100,
            }),
            Err(ReferenceDomainError::Forbidden)
        );
        model.apply(ReferenceDomainStep::Invite {
            actor: 1,
            target: 3,
            instance: 20,
            invite: 1,
            expires_at: 100,
        })?;
        assert_eq!(
            model.apply(ReferenceDomainStep::Invite {
                actor: 1,
                target: 3,
                instance: 20,
                invite: 1,
                expires_at: 100,
            }),
            Err(ReferenceDomainError::Duplicate)
        );

        let channel = model
            .channels
            .get_mut(&20)
            .ok_or(ReferenceDomainError::InvariantViolation)?;
        channel.invites.clear();
        for invite in 0..MAX_REFERENCE_INVITES {
            let invite = u16::try_from(invite).map_err(|_| ReferenceDomainError::Overflow)?;
            channel.invites.insert(invite, (3, 1, 100));
        }
        assert_eq!(
            model.invite(1, 3, 20, 300, 100),
            Err(ReferenceDomainError::LimitExceeded)
        );

        let mut corrupt = joined_model()?;
        corrupt.session_ids.clear();
        assert_eq!(
            corrupt.validate(),
            Err(ReferenceDomainError::InvariantViolation)
        );
        let mut corrupt = joined_model()?;
        corrupt.nicknames.clear();
        assert_eq!(
            corrupt.validate_sessions(),
            Err(ReferenceDomainError::InvariantViolation)
        );
        let mut corrupt = joined_model()?;
        corrupt.channel_names.clear();
        assert_eq!(
            corrupt.validate(),
            Err(ReferenceDomainError::InvariantViolation)
        );
        let mut corrupt = joined_model()?;
        corrupt
            .sessions
            .get_mut(&1)
            .ok_or(ReferenceDomainError::InvariantViolation)?
            .channels
            .insert(99);
        assert_eq!(
            corrupt.validate_sessions(),
            Err(ReferenceDomainError::InvariantViolation)
        );
        let mut corrupt = joined_model()?;
        corrupt
            .channels
            .get_mut(&20)
            .ok_or(ReferenceDomainError::InvariantViolation)?
            .members
            .insert(99, ReferenceRole::Member);
        assert_eq!(
            corrupt.validate_channels(),
            Err(ReferenceDomainError::InvariantViolation)
        );
        Ok(())
    }

    #[test]
    fn reference_hard_limits_and_checked_overflow_are_observable()
    -> Result<(), ReferenceDomainError> {
        let mut accounts = ReferenceDomainModel::new();
        for account in 0..MAX_REFERENCE_ACCOUNTS {
            let account = u16::try_from(account).map_err(|_| ReferenceDomainError::Overflow)?;
            accounts.create_account(account, 1)?;
        }
        assert_eq!(
            accounts.create_account(100, 1),
            Err(ReferenceDomainError::LimitExceeded)
        );

        let mut sessions = ReferenceDomainModel::new();
        for user in 0..MAX_REFERENCE_SESSIONS {
            let user = u16::try_from(user).map_err(|_| ReferenceDomainError::Overflow)?;
            sessions.open_session(
                user,
                ReferenceSession {
                    session: user,
                    account: None,
                    account_generation: 0,
                    session_generation: 1,
                    nickname: format!("user{user}"),
                    cloak: u32::from(user),
                    channels: BTreeSet::new(),
                },
            )?;
        }
        assert_eq!(
            sessions.open_session(
                500,
                ReferenceSession {
                    session: 500,
                    account: None,
                    account_generation: 0,
                    session_generation: 1,
                    nickname: "overflow".to_owned(),
                    cloak: 500,
                    channels: BTreeSet::new(),
                },
            ),
            Err(ReferenceDomainError::LimitExceeded)
        );

        let mut overflow = ReferenceDomainModel::new();
        overflow.revision = u64::MAX;
        assert_eq!(
            overflow.apply(ReferenceDomainStep::CreateAccount {
                account: 1,
                generation: 1,
            }),
            Err(ReferenceDomainError::Overflow)
        );
        overflow.revision = 0;
        overflow.federation_sequences.insert(1, u64::MAX);
        assert_eq!(
            overflow.federation_apply(1, u64::MAX),
            Err(ReferenceDomainError::Overflow)
        );
        overflow.sessions.insert(
            1,
            ReferenceSession {
                session: 1,
                account: None,
                account_generation: 0,
                session_generation: u64::MAX,
                nickname: "overflow".to_owned(),
                cloak: 1,
                channels: BTreeSet::new(),
            },
        );
        assert_eq!(
            overflow.switch_account(1, None, u64::MAX, 0),
            Err(ReferenceDomainError::Overflow)
        );
        Ok(())
    }

    #[test]
    fn reference_guard_matrix_covers_limits_roles_and_reverse_indexes()
    -> Result<(), ReferenceDomainError> {
        assert_eq!(
            validate_name(&"x".repeat(MAX_REFERENCE_NAME_BYTES + 1)),
            Err(ReferenceDomainError::Invalid)
        );

        let mut model = joined_model()?;
        let revision = model.revision;
        model.apply(ReferenceDomainStep::ExecuteCommand {
            user: 1,
            command: ReferenceCommand::Query(ReferenceCommandKind::Who),
        })?;
        assert_eq!(model.revision, revision);
        model.apply(ReferenceDomainStep::Part {
            user: 2,
            instance: 20,
        })?;
        assert!(model.channels.contains_key(&20));

        let mut destroy = ReferenceDomainModel::new();
        destroy.apply(open(1, 11, "sole-owner"))?;
        destroy.apply(ReferenceDomainStep::Join {
            user: 1,
            channel: "#destroy".to_owned(),
            instance: 21,
        })?;
        destroy.apply(ReferenceDomainStep::Part {
            user: 1,
            instance: 21,
        })?;
        assert!(!destroy.channels.contains_key(&21));

        let mut low_role = joined_model()?;
        assert_eq!(
            low_role.set_role(2, 1, 20, ReferenceRole::Voice),
            Err(ReferenceDomainError::Forbidden)
        );

        let mut roles = joined_model()?;
        roles
            .channels
            .get_mut(&20)
            .ok_or(ReferenceDomainError::InvariantViolation)?
            .members
            .insert(1, ReferenceRole::Operator);
        assert_eq!(
            roles.set_role(1, 2, 20, ReferenceRole::Administrator),
            Err(ReferenceDomainError::Forbidden)
        );
        let channel = roles
            .channels
            .get_mut(&20)
            .ok_or(ReferenceDomainError::InvariantViolation)?;
        channel.members.insert(1, ReferenceRole::Owner);
        channel.members.insert(2, ReferenceRole::Owner);
        assert_eq!(
            roles.set_role(1, 2, 20, ReferenceRole::Member),
            Err(ReferenceDomainError::Forbidden)
        );
        roles
            .channels
            .get_mut(&20)
            .ok_or(ReferenceDomainError::InvariantViolation)?
            .members
            .insert(2, ReferenceRole::Member);
        assert_eq!(
            roles.set_visibility(2, 20, ReferenceVisibility::Secret),
            Err(ReferenceDomainError::Forbidden)
        );
        assert_eq!(
            roles.invite(2, 3, 20, 7, 100),
            Err(ReferenceDomainError::Forbidden)
        );

        let mut member_limited = joined_model()?;
        let channel = member_limited
            .channels
            .get_mut(&20)
            .ok_or(ReferenceDomainError::InvariantViolation)?;
        for user in 0..MAX_REFERENCE_MEMBERS {
            channel.members.insert(
                u16::try_from(user).map_err(|_| ReferenceDomainError::Overflow)?,
                ReferenceRole::Member,
            );
        }
        assert_eq!(
            member_limited.join(3, "#reference".to_owned(), 20),
            Err(ReferenceDomainError::LimitExceeded)
        );

        let mut channels = ReferenceDomainModel::new();
        channels.apply(open(1, 1, "creator"))?;
        for instance in 0..MAX_REFERENCE_CHANNELS {
            let instance = u16::try_from(instance).map_err(|_| ReferenceDomainError::Overflow)?;
            let name = format!("#channel{instance}");
            channels.channel_names.insert(name.clone(), instance);
            channels.channels.insert(
                instance,
                ReferenceChannel {
                    name,
                    members: BTreeMap::new(),
                    visibility: ReferenceVisibility::Listed,
                    invites: BTreeMap::new(),
                },
            );
        }
        assert_eq!(
            channels.insert_channel(1, "#overflow".to_owned(), 500),
            Err(ReferenceDomainError::LimitExceeded)
        );
        let mut duplicate_instance = ReferenceDomainModel::new();
        duplicate_instance.apply(open(1, 1, "creator"))?;
        duplicate_instance.channels.insert(
            10,
            ReferenceChannel {
                name: "#existing".to_owned(),
                members: BTreeMap::new(),
                visibility: ReferenceVisibility::Listed,
                invites: BTreeMap::new(),
            },
        );
        assert_eq!(
            duplicate_instance.insert_channel(1, "#other".to_owned(), 10),
            Err(ReferenceDomainError::LimitExceeded)
        );
        let mut missing_creator = ReferenceDomainModel::new();
        assert_eq!(
            missing_creator.insert_channel(99, "#orphan".to_owned(), 10),
            Err(ReferenceDomainError::InvariantViolation)
        );

        let mut corrupt = joined_model()?;
        corrupt.session_ids.clear();
        corrupt.session_ids.insert(99);
        assert_eq!(
            corrupt.validate_sessions(),
            Err(ReferenceDomainError::InvariantViolation)
        );
        let mut corrupt = joined_model()?;
        corrupt.nicknames.clear();
        corrupt.nicknames.insert("wrong".to_owned(), 1);
        corrupt.nicknames.insert("also-wrong".to_owned(), 2);
        corrupt.nicknames.insert("outsider".to_owned(), 3);
        assert_eq!(
            corrupt.validate_sessions(),
            Err(ReferenceDomainError::InvariantViolation)
        );
        let mut corrupt = joined_model()?;
        corrupt.channel_names.clear();
        corrupt.channel_names.insert("#wrong".to_owned(), 20);
        assert_eq!(
            corrupt.validate_channels(),
            Err(ReferenceDomainError::InvariantViolation)
        );
        let mut corrupt = joined_model()?;
        let session = corrupt
            .sessions
            .get_mut(&1)
            .ok_or(ReferenceDomainError::InvariantViolation)?;
        session.account = Some(99);
        session.account_generation = 1;
        assert_eq!(
            corrupt.validate_sessions(),
            Err(ReferenceDomainError::NotFound)
        );
        corrupt
            .accounts
            .insert(99, ReferenceAccount { generation: 2 });
        assert_eq!(
            corrupt.validate_sessions(),
            Err(ReferenceDomainError::Stale)
        );
        Ok(())
    }

    #[test]
    fn reference_short_circuits_and_command_indexes_fail_closed() -> Result<(), ReferenceDomainError>
    {
        let mut base = joined_model()?;

        let mut switching = base.clone();
        assert_eq!(switching.create_account(7, 1), Ok(true));
        assert_eq!(switching.switch_account(1, None, 1, 0), Ok(true));
        assert_eq!(switching.switch_account(1, Some(7), 2, 1), Ok(true));
        assert_eq!(switching.switch_account(1, Some(7), 3, 1), Ok(true));

        assert_eq!(base.kick(1, 1, 20), Err(ReferenceDomainError::Forbidden));
        assert_eq!(
            base.route_message(
                1,
                ReferenceCommandKind::Privmsg,
                ReferenceMessageTarget::User(2),
            ),
            Ok(false)
        );

        let mut monitored = base.clone();
        monitored
            .monitors
            .insert(1, BTreeSet::from(["member".to_owned()]));
        assert!(monitored.monitor_remove(1, "member"));

        let mut corrupt = base.clone();
        corrupt.nicknames.remove("owner");
        assert_eq!(
            corrupt.validate(),
            Err(ReferenceDomainError::InvariantViolation)
        );

        let mut corrupt = base.clone();
        corrupt.away_users.insert(99);
        assert_eq!(
            corrupt.validate_command_state(),
            Err(ReferenceDomainError::InvariantViolation)
        );

        let mut corrupt = base.clone();
        corrupt.monitors.insert(
            1,
            (0..=MAX_REFERENCE_MONITORS)
                .map(|index| format!("monitor{index}"))
                .collect(),
        );
        assert_eq!(
            corrupt.validate_command_state(),
            Err(ReferenceDomainError::InvariantViolation)
        );

        let mut corrupt = base.clone();
        corrupt.account_updates.insert(99, 1);
        assert_eq!(
            corrupt.validate_command_state(),
            Err(ReferenceDomainError::InvariantViolation)
        );

        let mut corrupt = base;
        corrupt.topics.insert(99);
        assert_eq!(
            corrupt.validate_command_state(),
            Err(ReferenceDomainError::InvariantViolation)
        );
        Ok(())
    }
}
