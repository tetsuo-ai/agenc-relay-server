//! Coordinator-side derivation of least-information events and standing
//! projection deltas for every target edge (spec 20.6, 20.8, B.4, B.5).
//!
//! The derivation runs before the storage commit, because the outbox rows
//! it produces belong to the same transaction as the mutation. It therefore
//! never looks at an applied state: it reads the committed pre-state and
//! overlays the plan's own durable after-images on top of it. Nothing here
//! allocates identities, encodes bytes, or touches a socket.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use agenc_relay_types::{
    AccountId, ChannelInstanceId, InviteId, MessageId, Revision, ServerId, UserId,
};

use crate::federation::record::{
    AccountRecord, ActorView, ChannelDetailRecord, DeliveredMessageRecord, DeliveryTarget,
    InviteRecord, InviteRemovalKind, MembershipRecord, MembershipView, ModeDirection,
    ModeListEntryRecord, ProjectedEvent, ProjectedModeChange, ProjectionKey, ProjectionRecord,
    SessionEventView, SessionHideKind, SessionRecord, SourceView,
};
use crate::{
    DomainError, DomainEvent, DomainState, DurableAccount, DurableChannel, DurableInvite,
    DurableListEntry, DurableMembership, DurableSession, DurableWrite, MessageKind, MutationPlan,
    NicknameValue, Principal, ResolvedMessageTarget, Role, Visibility,
};

/// Simple-mode bit for `i`.
const MODE_BIT_INVITE_ONLY: u16 = 1;
/// Simple-mode bit for `m`.
const MODE_BIT_MODERATED: u16 = 1 << 1;
/// Simple-mode bit for `n`; always set.
const MODE_BIT_NO_EXTERNAL: u16 = 1 << 2;
/// Simple-mode bit for `p`.
const MODE_BIT_PRIVATE: u16 = 1 << 3;
/// Simple-mode bit for `s`.
const MODE_BIT_SECRET: u16 = 1 << 4;
/// Simple-mode bit for `t`.
const MODE_BIT_TOPIC_PROTECTED: u16 = 1 << 5;
/// User-mode bit for `i`; always set.
const USER_MODE_BIT_INVISIBLE: u16 = 1;
/// User-mode bit for `w`.
const USER_MODE_BIT_WALLOPS: u16 = 1 << 1;
const MODE_CODE_BAN: u16 = 1;
const MODE_CODE_EXCEPTION: u16 = 2;
const MODE_CODE_INVITE_EXCEPTION: u16 = 3;
const MODE_CODE_INVITE_ONLY: u16 = 6;
const MODE_CODE_MODERATED: u16 = 7;
const MODE_CODE_PRIVATE: u16 = 9;
const MODE_CODE_SECRET: u16 = 10;
const MODE_CODE_TOPIC_PROTECTED: u16 = 11;

/// Runtime-supplied intent that the plan alone cannot express.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MutationContext {
    /// The acting user for topic, mode, kick, invite, and recompute events.
    pub actor: Option<UserId>,
    /// The client-supplied reason for a part, kick, or quit.
    pub reason: String,
    /// Whether `Parted` events represent kicks by `actor`.
    pub kicked: bool,
    /// Why hidden sessions disappeared.
    pub hide_kind: Option<SessionHideKind>,
    /// The resolved User ID of an invite's named nickname target.
    pub named_target: Option<UserId>,
    /// Validated client-only tags of an accepted message, sorted by key.
    pub client_tags: Vec<(String, String)>,
    /// The acceptance time of a message in UTC milliseconds.
    pub received_unix_milliseconds: u64,
}

/// What one edge currently holds, by key.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EdgeStanding {
    channels: BTreeMap<ChannelInstanceId, Revision>,
    invites: BTreeSet<(ChannelInstanceId, InviteId)>,
    accounts: BTreeSet<AccountId>,
    sessions: BTreeSet<UserId>,
    memberships: BTreeSet<(ChannelInstanceId, UserId)>,
}

impl EdgeStanding {
    /// Returns the number of standing entries.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.channels
            .len()
            .saturating_add(self.invites.len())
            .saturating_add(self.accounts.len())
            .saturating_add(self.sessions.len())
            .saturating_add(self.memberships.len())
    }

    /// Reports whether the edge holds a detail for the channel.
    #[must_use]
    pub fn holds_channel(&self, channel_id: ChannelInstanceId) -> bool {
        self.channels.contains_key(&channel_id)
    }

    /// Reports whether the edge holds a copy of the invite.
    #[must_use]
    pub fn holds_invite(&self, channel_id: ChannelInstanceId, invite_id: InviteId) -> bool {
        self.invites.contains(&(channel_id, invite_id))
    }

    /// Reports whether the edge holds the account projection.
    #[must_use]
    pub fn holds_account(&self, account_id: AccountId) -> bool {
        self.accounts.contains(&account_id)
    }

    /// Reports whether the edge holds the session projection.
    #[must_use]
    pub fn holds_session(&self, user_id: UserId) -> bool {
        self.sessions.contains(&user_id)
    }

    /// Iterates every standing key in snapshot order.
    pub fn keys(&self) -> impl Iterator<Item = ProjectionKey> + '_ {
        let sessions = self
            .sessions
            .iter()
            .map(|user| ProjectionKey::session(*user));
        let channels = self
            .channels
            .keys()
            .map(|channel| ProjectionKey::channel_detail(*channel));
        let memberships = self
            .memberships
            .iter()
            .map(|(channel, user)| ProjectionKey::membership(*channel, *user));
        let invites = self
            .invites
            .iter()
            .map(|(channel, invite)| ProjectionKey::invite(*channel, *invite));
        let accounts = self
            .accounts
            .iter()
            .map(|account| ProjectionKey::account(*account));
        sessions
            .chain(channels)
            .chain(memberships)
            .chain(invites)
            .chain(accounts)
    }

    fn insert(&mut self, record: &ProjectionRecord) {
        match record {
            ProjectionRecord::Session(record) => {
                self.sessions.insert(record.user_id);
            }
            ProjectionRecord::ChannelDetail(record) => {
                self.channels
                    .insert(record.channel_id, record.channel_revision);
            }
            ProjectionRecord::Membership(record) => {
                self.memberships.insert((record.channel_id, record.user_id));
            }
            ProjectionRecord::Invite(record) => {
                self.invites.insert((record.channel_id, record.invite_id));
            }
            ProjectionRecord::Account(record) => {
                self.accounts.insert(record.account_id);
            }
        }
    }

    fn remove(&mut self, key: &ProjectionKey) -> bool {
        let Some(leading) = key.primary().get(..16) else {
            return match key.kind() {
                ProjectionKey::ACCOUNT => self.remove_account(key.primary()),
                _ => false,
            };
        };
        let Ok(leading) = <[u8; 16]>::try_from(leading) else {
            return false;
        };
        match key.kind() {
            ProjectionKey::SESSION => self.sessions.remove(&UserId::from_bytes(leading)),
            ProjectionKey::CHANNEL_DETAIL => self
                .channels
                .remove(&ChannelInstanceId::from_bytes(leading))
                .is_some(),
            ProjectionKey::MEMBERSHIP => {
                let Some(user) = trailing_id(key.primary()) else {
                    return false;
                };
                self.memberships.remove(&(
                    ChannelInstanceId::from_bytes(leading),
                    UserId::from_bytes(user),
                ))
            }
            ProjectionKey::INVITE => {
                let Some(invite) = trailing_id(key.primary()) else {
                    return false;
                };
                self.invites.remove(&(
                    ChannelInstanceId::from_bytes(leading),
                    InviteId::from_bytes(invite),
                ))
            }
            ProjectionKey::ACCOUNT => self.remove_account(key.primary()),
            _ => false,
        }
    }

    fn remove_account(&mut self, primary: &[u8]) -> bool {
        AccountId::parse_wire_bytes(primary)
            .ok()
            .is_some_and(|account| self.accounts.remove(&account))
    }
}

fn trailing_id(primary: &[u8]) -> Option<[u8; 16]> {
    primary.get(16..32)?.try_into().ok()
}

/// The event copies and standing deltas for one target edge.
#[derive(Clone, Eq, PartialEq)]
pub struct EdgeDelta {
    /// The target edge.
    pub target: ServerId,
    /// Event copies in delivery order.
    pub events: Vec<ProjectedEvent>,
    /// Standing entries to insert or replace.
    pub upserts: Vec<ProjectionRecord>,
    /// Standing entries to delete.
    pub removals: Vec<ProjectionKey>,
}

impl EdgeDelta {
    fn empty(target: ServerId) -> Self {
        Self {
            target,
            events: Vec::new(),
            upserts: Vec::new(),
            removals: Vec::new(),
        }
    }
}

/// Everything one mutation projects, grouped per edge in Server ID order.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct MutationProjection {
    /// Per-edge deltas.
    pub edges: Vec<EdgeDelta>,
}

impl MutationProjection {
    /// Returns the total number of event copies.
    #[must_use]
    pub fn event_count(&self) -> usize {
        self.edges.iter().map(|delta| delta.events.len()).sum()
    }
}

struct Emission {
    target_index: u16,
    edge: ServerId,
    event: ProjectedEvent,
}

#[derive(Default)]
struct StandingDelta {
    upserts: Vec<ProjectionRecord>,
    removals: Vec<ProjectionKey>,
}

struct ResolvedDelivery {
    target: DeliveryTarget,
    target_revision: Revision,
    sequence: u64,
    edges: BTreeSet<ServerId>,
}

/// The coordinator's standing index of every edge's projection.
pub struct CoordinatorProjection {
    local_server_id: ServerId,
    edges: BTreeMap<ServerId, EdgeStanding>,
}

impl CoordinatorProjection {
    /// Creates an index for a coordinator with the given local identity.
    #[must_use]
    pub fn new(local_server_id: ServerId) -> Self {
        Self {
            local_server_id,
            edges: BTreeMap::new(),
        }
    }

    /// Returns one edge's standing view.
    #[must_use]
    pub fn edge(&self, edge: ServerId) -> Option<&EdgeStanding> {
        self.edges.get(&edge)
    }

    /// Restores one standing key from durable storage.
    pub fn restore_key(&mut self, edge: ServerId, record: &ProjectionRecord) {
        self.edges.entry(edge).or_default().insert(record);
    }

    /// Commits a derived projection into the standing index after the
    /// storage transaction that carried it is durable.
    pub fn apply(&mut self, projection: &MutationProjection) {
        for delta in &projection.edges {
            let standing = self.edges.entry(delta.target).or_default();
            for key in &delta.removals {
                standing.remove(key);
            }
            for record in &delta.upserts {
                standing.insert(record);
            }
        }
    }

    /// Derives the complete standing projection of one edge from the live
    /// state: the snapshot cut of spec 20.9, in B.4 `(kind, primary)` order.
    /// The incremental deltas converge to exactly this set.
    #[must_use]
    pub fn standing_of(domain: &DomainState, edge: ServerId) -> Vec<ProjectionRecord> {
        let view = CutView::new(domain, edge);
        let mut records = Vec::new();
        view.sessions(&mut records);
        view.channels(&mut records);
        view.memberships(&mut records);
        view.invites(&mut records);
        view.accounts(&mut records);
        records
    }

    /// Replaces one edge's standing with a snapshot cut.
    pub fn install_edge(&mut self, edge: ServerId, records: &[ProjectionRecord]) {
        let mut standing = EdgeStanding::default();
        for record in records {
            standing.insert(record);
        }
        self.edges.insert(edge, standing);
    }

    /// Derives every event copy and standing delta for one plan that has
    /// been prepared against `base` but not yet applied.
    pub fn derive(
        &self,
        base: &DomainState,
        plan: &MutationPlan,
        context: &MutationContext,
    ) -> Result<MutationProjection, DomainError> {
        if plan.expected_revision() != base.revision() {
            return Err(DomainError::StaleRevision);
        }
        let view = Overlay::new(base, plan);
        let mut derivation = Derivation {
            index: self,
            view,
            plan,
            context,
            emissions: Vec::new(),
            touched_channels: BTreeSet::new(),
            touched_users: BTreeSet::new(),
            touched_accounts: BTreeSet::new(),
        };
        for (position, event) in plan.events().iter().enumerate() {
            let target_index = u16::try_from(position).map_err(|_| DomainError::LimitExceeded)?;
            derivation.project_event(target_index, event)?;
        }
        derivation.finish()
    }
}

/// The live sessions and channels an edge's snapshot cut is read from.
struct CutView<'a> {
    domain: &'a DomainState,
    edge: ServerId,
    sessions: Vec<DurableSession>,
    channels: Vec<DurableChannel>,
}

impl<'a> CutView<'a> {
    fn new(domain: &'a DomainState, edge: ServerId) -> Self {
        let sessions = domain
            .session_user_ids()
            .filter_map(|user| domain.durable_session(user))
            .collect();
        let mut channels: Vec<DurableChannel> = domain.durable_channels().collect();
        channels.sort_by(|left, right| left.channel_id.as_bytes().cmp(right.channel_id.as_bytes()));
        Self {
            domain,
            edge,
            sessions,
            channels,
        }
    }

    fn home_of(&self, user: UserId) -> Option<ServerId> {
        self.sessions
            .iter()
            .find(|session| session.user_id == user)
            .map(|session| session.home_server_id)
    }

    fn hosts(&self, principal: Principal) -> bool {
        match principal {
            Principal::Guest(user) => self.home_of(user) == Some(self.edge),
            Principal::Account(account) => self.sessions.iter().any(|session| {
                session.home_server_id == self.edge && session.account_id == Some(account)
            }),
        }
    }

    fn entitled(&self, channel: &DurableChannel) -> bool {
        channel
            .memberships
            .iter()
            .any(|membership| self.home_of(membership.user_id) == Some(self.edge))
            || channel
                .invites
                .iter()
                .any(|invite| self.hosts(invite.target))
    }

    fn sessions(&self, records: &mut Vec<ProjectionRecord>) {
        for session in self
            .sessions
            .iter()
            .filter(|session| session.home_server_id == self.edge)
        {
            let label = session
                .account_id
                .and_then(|account| self.domain.durable_account(account))
                .and_then(|account| account.label);
            records.push(ProjectionRecord::Session(session_record_from(
                session, label,
            )));
        }
    }

    fn channels(&self, records: &mut Vec<ProjectionRecord>) {
        for channel in self
            .channels
            .iter()
            .filter(|channel| self.entitled(channel))
        {
            records.push(ProjectionRecord::ChannelDetail(channel_detail_from(
                channel,
            )));
        }
    }

    fn memberships(&self, records: &mut Vec<ProjectionRecord>) {
        for channel in self
            .channels
            .iter()
            .filter(|channel| self.entitled(channel))
        {
            let mut memberships: Vec<&DurableMembership> = channel
                .memberships
                .iter()
                .filter(|membership| self.home_of(membership.user_id) == Some(self.edge))
                .collect();
            memberships
                .sort_by(|left, right| left.user_id.as_bytes().cmp(right.user_id.as_bytes()));
            for membership in memberships {
                records.push(ProjectionRecord::Membership(MembershipRecord {
                    channel_id: channel.channel_id,
                    user_id: membership.user_id,
                    role: membership.effective_role,
                    membership_revision: membership.membership_revision,
                    joined_at: membership.joined_at,
                }));
            }
        }
    }

    fn invites(&self, records: &mut Vec<ProjectionRecord>) {
        for channel in &self.channels {
            let mut invites: Vec<&DurableInvite> = channel
                .invites
                .iter()
                .filter(|invite| self.hosts(invite.target))
                .collect();
            invites
                .sort_by(|left, right| left.invite_id.as_bytes().cmp(right.invite_id.as_bytes()));
            for invite in invites {
                records.push(ProjectionRecord::Invite(InviteRecord {
                    channel_id: channel.channel_id,
                    invite_id: invite.invite_id,
                    target: invite.target,
                    inviter_user_id: invite.inviter,
                    creation_revision: invite.creation_revision,
                    expires_at: invite.expires_at_utc,
                }));
            }
        }
    }

    fn accounts(&self, records: &mut Vec<ProjectionRecord>) {
        let mut hosted: Vec<AccountId> = self
            .sessions
            .iter()
            .filter(|session| session.home_server_id == self.edge)
            .filter_map(|session| session.account_id)
            .collect();
        hosted.sort_unstable();
        hosted.dedup();
        for account_id in hosted {
            if let Some(account) = self.domain.durable_account(account_id) {
                records.push(ProjectionRecord::Account(AccountRecord {
                    account_id,
                    account_session_generation: account.session_generation,
                    account_revision: account.revision,
                }));
            }
        }
    }
}

/// The committed pre-state with the plan's after-images laid over it.
struct Overlay<'a> {
    base: &'a DomainState,
    sessions: BTreeMap<UserId, Option<DurableSession>>,
    channels: BTreeMap<ChannelInstanceId, Option<DurableChannel>>,
    accounts: BTreeMap<AccountId, Option<DurableAccount>>,
}

impl<'a> Overlay<'a> {
    fn new(base: &'a DomainState, plan: &MutationPlan) -> Self {
        let mut overlay = Self {
            base,
            sessions: BTreeMap::new(),
            channels: BTreeMap::new(),
            accounts: BTreeMap::new(),
        };
        for write in plan.durable_writes() {
            overlay.lay(write);
        }
        overlay
    }

    fn lay(&mut self, write: &DurableWrite) {
        match write {
            DurableWrite::PutSession(session) => {
                self.sessions.insert(session.user_id, Some(session.clone()));
            }
            DurableWrite::TombstoneSession(session_id) => {
                if let Some(user_id) = self.base.session_ids.get(session_id) {
                    self.sessions.insert(*user_id, None);
                }
            }
            DurableWrite::PutChannel(channel) => {
                self.channels
                    .insert(channel.channel_id, Some(channel.clone()));
            }
            DurableWrite::TombstoneChannel { channel_id, .. } => {
                self.channels.insert(*channel_id, None);
            }
            DurableWrite::PutAccount(account) => {
                self.accounts
                    .insert(account.account_id, Some(account.clone()));
            }
            DurableWrite::TombstoneAccount(account_id) => {
                self.accounts.insert(*account_id, None);
            }
            DurableWrite::AppendSanction(_) => {}
        }
    }

    fn pre_session(&self, user_id: UserId) -> Option<DurableSession> {
        self.base.durable_session(user_id)
    }

    fn post_session(&self, user_id: UserId) -> Option<Cow<'_, DurableSession>> {
        match self.sessions.get(&user_id) {
            Some(Some(session)) => Some(Cow::Borrowed(session)),
            Some(None) => None,
            None => self.base.durable_session(user_id).map(Cow::Owned),
        }
    }

    fn post_sessions(&self) -> Vec<Cow<'_, DurableSession>> {
        let mut sessions: Vec<Cow<'_, DurableSession>> = self
            .base
            .session_user_ids()
            .filter(|user| !self.sessions.contains_key(user))
            .filter_map(|user| self.base.durable_session(user).map(Cow::Owned))
            .collect();
        sessions.extend(self.sessions.values().flatten().map(Cow::Borrowed));
        sessions
    }

    fn pre_channel(&self, channel_id: ChannelInstanceId) -> Option<DurableChannel> {
        self.base.durable_channel(channel_id)
    }

    fn post_channel(&self, channel_id: ChannelInstanceId) -> Option<Cow<'_, DurableChannel>> {
        match self.channels.get(&channel_id) {
            Some(Some(channel)) => Some(Cow::Borrowed(channel)),
            Some(None) => None,
            None => self.base.durable_channel(channel_id).map(Cow::Owned),
        }
    }

    fn post_channels(&self) -> Vec<Cow<'_, DurableChannel>> {
        let mut channels: Vec<Cow<'_, DurableChannel>> = self
            .base
            .durable_channels()
            .filter(|channel| !self.channels.contains_key(&channel.channel_id))
            .map(Cow::Owned)
            .collect();
        channels.extend(self.channels.values().flatten().map(Cow::Borrowed));
        channels
    }

    fn pre_account(&self, account_id: AccountId) -> Option<DurableAccount> {
        self.base.durable_account(account_id)
    }

    fn post_account(&self, account_id: AccountId) -> Option<Cow<'_, DurableAccount>> {
        match self.accounts.get(&account_id) {
            Some(Some(account)) => Some(Cow::Borrowed(account)),
            Some(None) => None,
            None => self.base.durable_account(account_id).map(Cow::Owned),
        }
    }

    /// Edges with a live session that monitors the nickname; MONITOR sets are
    /// process-local, so the committed base state is authoritative.
    fn monitor_edges(&self, nickname: &NicknameValue) -> BTreeSet<ServerId> {
        self.base
            .sessions
            .values()
            .filter(|session| session.monitored_nicknames.contains(nickname))
            .map(|session| session.home_server_id)
            .collect()
    }
}

struct Derivation<'a> {
    index: &'a CoordinatorProjection,
    view: Overlay<'a>,
    plan: &'a MutationPlan,
    context: &'a MutationContext,
    emissions: Vec<Emission>,
    touched_channels: BTreeSet<ChannelInstanceId>,
    touched_users: BTreeSet<UserId>,
    touched_accounts: BTreeSet<AccountId>,
}

impl Derivation<'_> {
    fn resulting_revision(&self) -> Revision {
        self.plan.resulting_revision()
    }

    fn emit(&mut self, target_index: u16, edge: ServerId, event: ProjectedEvent) {
        if edge == self.index.local_server_id {
            return;
        }
        self.emissions.push(Emission {
            target_index,
            edge,
            event,
        });
    }

    fn home_of(&self, user_id: UserId) -> Option<ServerId> {
        self.view
            .post_session(user_id)
            .map(|session| session.home_server_id)
            .or_else(|| {
                self.view
                    .pre_session(user_id)
                    .map(|session| session.home_server_id)
            })
    }

    fn label_of(&self, account_id: Option<AccountId>) -> Option<crate::AccountLabelValue> {
        account_id.and_then(|account| {
            self.view
                .post_account(account)
                .and_then(|account| account.label.clone())
        })
    }

    fn source_view(&self, user_id: UserId) -> Option<SourceView> {
        let session = self
            .view
            .post_session(user_id)
            .map(Cow::into_owned)
            .or_else(|| self.view.pre_session(user_id))?;
        let account_label = self.label_of(session.account_id).or_else(|| {
            session
                .account_id
                .and_then(|account| self.view.pre_account(account))
                .and_then(|account| account.label)
        });
        Some(SourceView {
            user_id,
            nickname: session.nickname,
            public_cloak: session.public_cloak,
            account_label,
        })
    }

    fn session_record(&self, user_id: UserId) -> Option<SessionRecord> {
        let session = self.view.post_session(user_id)?;
        let label = self.label_of(session.account_id);
        Some(session_record_from(&session, label))
    }

    fn event_view(&self, user_id: UserId, edge: ServerId) -> Option<SessionEventView> {
        let source = self.source_view(user_id)?;
        let home_projection = if self.home_of(user_id) == Some(edge) {
            self.session_record(user_id)
        } else {
            None
        };
        Some(SessionEventView {
            source,
            home_projection,
        })
    }

    /// Edges with a local member in the channel after apply.
    fn member_edges(&self, channel_id: ChannelInstanceId) -> BTreeSet<ServerId> {
        let Some(channel) = self.view.post_channel(channel_id) else {
            return BTreeSet::new();
        };
        channel
            .memberships
            .iter()
            .filter_map(|membership| self.home_of(membership.user_id))
            .collect()
    }

    /// Edges with a local member in the channel before apply.
    fn pre_member_edges(&self, channel_id: ChannelInstanceId) -> BTreeSet<ServerId> {
        let Some(channel) = self.view.pre_channel(channel_id) else {
            return BTreeSet::new();
        };
        channel
            .memberships
            .iter()
            .filter_map(|membership| self.home_of(membership.user_id))
            .collect()
    }

    /// Edges sharing at least one channel with the user after apply, or
    /// before apply when the user left.
    fn shared_edges(&self, user_id: UserId) -> BTreeSet<ServerId> {
        let mut edges = BTreeSet::new();
        if let Some(session) = self.view.post_session(user_id) {
            for channel_id in &session.joined_channels {
                edges.extend(self.member_edges(*channel_id));
            }
        } else if let Some(session) = self.view.pre_session(user_id) {
            for channel_id in &session.joined_channels {
                edges.extend(self.pre_member_edges(*channel_id));
            }
        }
        edges
    }

    /// Edges hosting the principal after apply.
    fn hosting_edges(&self, principal: Principal) -> BTreeSet<ServerId> {
        match principal {
            // A closed session hosts nothing, and neither does a guest
            // identity its session left by logging in.
            Principal::Guest(user_id) => self
                .view
                .post_session(user_id)
                .filter(|session| session.account_id.is_none())
                .map(|session| session.home_server_id)
                .into_iter()
                .collect(),
            Principal::Account(account_id) => self
                .view
                .post_sessions()
                .iter()
                .filter(|session| session.account_id == Some(account_id))
                .map(|session| session.home_server_id)
                .collect(),
        }
    }

    fn entitled_after(&self, edge: ServerId, channel_id: ChannelInstanceId) -> bool {
        let Some(channel) = self.view.post_channel(channel_id) else {
            return false;
        };
        if channel
            .memberships
            .iter()
            .any(|membership| self.home_of(membership.user_id) == Some(edge))
        {
            return true;
        }
        channel
            .invites
            .iter()
            .any(|invite| self.hosting_edges(invite.target).contains(&edge))
    }

    fn entitled_before(&self, edge: ServerId, channel_id: ChannelInstanceId) -> bool {
        self.index
            .edges
            .get(&edge)
            .is_some_and(|standing| standing.holds_channel(channel_id))
    }

    fn detail(&self, channel_id: ChannelInstanceId) -> Option<ChannelDetailRecord> {
        self.view
            .post_channel(channel_id)
            .map(|channel| channel_detail_from(&channel))
    }

    fn actor_view(&self) -> ActorView {
        ActorView(self.context.actor.and_then(|actor| self.source_view(actor)))
    }

    fn touch_channel(&mut self, channel_id: ChannelInstanceId) {
        self.touched_channels.insert(channel_id);
    }

    // agenc-review: focus owner=domain reviewed=2026-09-02 reason=one closed dispatcher maps every domain event kind onto its projection rule
    fn project_event(&mut self, index: u16, event: &DomainEvent) -> Result<(), DomainError> {
        match event {
            DomainEvent::SessionOpened(user) => self.project_session_opened(index, *user),
            DomainEvent::SessionAuthorityChanged(user) => {
                self.project_authority_changed(index, *user)
            }
            DomainEvent::SessionHidden(user) => {
                let kind = self
                    .context
                    .hide_kind
                    .unwrap_or(SessionHideKind::TransportLost);
                self.project_session_hidden(index, *user, kind)
            }
            DomainEvent::NicknameChanged(user) => self.project_nickname_changed(index, *user),
            DomainEvent::AwayChanged(user) => self.project_away_changed(index, *user),
            DomainEvent::UserModesChanged(user) => self.project_user_modes_changed(index, *user),
            DomainEvent::DisplayNameChanged(user) => {
                self.project_display_name_changed(index, *user)
            }
            DomainEvent::Joined(channel, user) => self.project_joined(index, *channel, *user),
            DomainEvent::Parted(channel, user) => {
                let hidden = self.plan.events().iter().any(
                    |other| matches!(other, DomainEvent::SessionHidden(hidden) if hidden == user),
                );
                if hidden {
                    self.touch_channel(*channel);
                    return Ok(());
                }
                self.project_parted(index, *channel, *user)
            }
            DomainEvent::ChannelCreated(channel) => {
                self.touch_channel(*channel);
                Ok(())
            }
            DomainEvent::ChannelDestroyed(channel) => {
                self.project_channel_destroyed(index, *channel);
                Ok(())
            }
            DomainEvent::TopicChanged(channel, message_id) => {
                self.project_topic_changed(index, *channel, *message_id)
            }
            DomainEvent::ChannelModesChanged(channel) => {
                self.project_modes_changed(index, *channel)
            }
            DomainEvent::ChannelMembershipsRecomputed(channel, account) => {
                self.project_recompute(index, *channel, *account)
            }
            DomainEvent::MessageAccepted(message_id, sender) => {
                self.project_message(index, *message_id, *sender)
            }
            DomainEvent::InviteCreated(channel, invite) => {
                self.project_invite_created(index, *channel, *invite)
            }
            DomainEvent::InviteExpired(channel, invite) => {
                self.project_invite_removed(index, *channel, *invite, InviteRemovalKind::Expired);
                self.touch_channel(*channel);
                Ok(())
            }
            DomainEvent::AccountUpdated(account) => self.project_account_updated(index, *account),
            DomainEvent::ChannelPolicyChanged(channel) => {
                self.project_policy_changed(index, *channel)
            }
            DomainEvent::AccountDeleted(account) => {
                self.project_account_sessions_gone(index, *account, SessionHideKind::AccountDeleted)
            }
            DomainEvent::AccountCredentialReplaced(account) => {
                self.project_account_sessions_gone(index, *account, SessionHideKind::SecurityFenced)
            }
            DomainEvent::AccountCreated(_)
            | DomainEvent::AccountDeletionChallengeStarted(_)
            | DomainEvent::AccountDeletionConfirmationRejected(_)
            | DomainEvent::E2eeRemovalPending(_, _)
            | DomainEvent::SanctionRecorded(_) => Ok(()),
        }
    }

    fn project_session_opened(&mut self, index: u16, user_id: UserId) -> Result<(), DomainError> {
        self.touched_users.insert(user_id);
        let Some(home) = self.home_of(user_id) else {
            return Ok(());
        };
        let Some(view) = self.event_view(user_id, home) else {
            return Ok(());
        };
        let nickname = view.source.nickname.clone();
        self.emit(index, home, ProjectedEvent::SessionVisible(view));
        for edge in self.view.monitor_edges(&nickname) {
            if edge == home {
                continue;
            }
            if let Some(view) = self.event_view(user_id, edge) {
                self.emit(index, edge, ProjectedEvent::SessionVisible(view));
            }
        }
        self.project_account_hosting(index, user_id, home);
        self.reproject_account_invites(index, user_id, home)
    }

    fn project_authority_changed(
        &mut self,
        index: u16,
        user_id: UserId,
    ) -> Result<(), DomainError> {
        self.touched_users.insert(user_id);
        let previous = self.view.pre_session(user_id);
        if let Some(account_id) = previous.as_ref().and_then(|session| session.account_id) {
            self.touched_accounts.insert(account_id);
        }
        let Some(home) = self.home_of(user_id) else {
            return Ok(());
        };
        if let Some(previous) = previous {
            self.project_principal_invites_hidden(index, principal_of(&previous), home);
            self.project_member_authority(index, user_id, &previous.joined_channels);
        }
        if let Some(view) = self.event_view(user_id, home) {
            self.emit(index, home, ProjectedEvent::SessionVisible(view));
        }
        self.project_account_hosting(index, user_id, home);
        self.reproject_account_invites(index, user_id, home)?;
        self.project_login(index, user_id);
        Ok(())
    }

    /// A guest session that logged in names its account, as an account label
    /// change does, to every edge that shares a channel with it and to its
    /// home edge, which render `ACCOUNT` for their `account-notify` clients
    /// (architecture 11.4). A logout is not projected this way.
    fn project_login(&mut self, index: u16, user_id: UserId) {
        let logged_in = self
            .view
            .pre_session(user_id)
            .is_some_and(|session| session.account_id.is_none())
            && self
                .view
                .post_session(user_id)
                .is_some_and(|session| session.account_id.is_some());
        if !logged_in {
            return;
        }
        let mut edges = self.shared_edges(user_id);
        edges.extend(self.home_of(user_id));
        for edge in edges {
            if let Some(view) = self.event_view(user_id, edge) {
                self.emit(index, edge, ProjectedEvent::AccountLabelChanged(view));
            }
        }
    }

    /// An account switch recomputes the session's membership in every joined
    /// channel and advances that channel, so each member edge takes the
    /// resulting revision and the home edge the recomputed role.
    fn project_member_authority(
        &mut self,
        index: u16,
        user_id: UserId,
        joined: &[ChannelInstanceId],
    ) {
        let resulting = self.resulting_revision();
        let actor = self.actor_view();
        for channel_id in joined.iter().copied() {
            let advanced = self
                .view
                .post_channel(channel_id)
                .is_some_and(|channel| channel.revision == resulting);
            let Some(view) = self
                .membership_view(channel_id, user_id)
                .filter(|_| advanced)
            else {
                continue;
            };
            self.touch_channel(channel_id);
            for edge in self.member_edges(channel_id) {
                self.emit(
                    index,
                    edge,
                    ProjectedEvent::ChannelMembershipsRecomputed {
                        channel_id,
                        resulting_revision: resulting,
                        actor: actor.clone(),
                        memberships: vec![view.clone()],
                    },
                );
            }
        }
    }

    /// Emits the account projection to the home edge when it is new there.
    fn project_account_hosting(&mut self, index: u16, user_id: UserId, home: ServerId) {
        let Some(account_id) = self
            .view
            .post_session(user_id)
            .and_then(|session| session.account_id)
        else {
            return;
        };
        self.touched_accounts.insert(account_id);
        let already = self
            .index
            .edges
            .get(&home)
            .is_some_and(|standing| standing.holds_account(account_id));
        if already {
            return;
        }
        if let Some(record) = self.account_record(account_id) {
            self.emit(index, home, ProjectedEvent::AccountStateChanged(record));
        }
    }

    /// Reprojects every live invite targeting the session's principal as an
    /// ordinary target-only `invited` event when the edge does not hold it.
    fn reproject_account_invites(
        &mut self,
        index: u16,
        user_id: UserId,
        home: ServerId,
    ) -> Result<(), DomainError> {
        let Some(principal) = self
            .view
            .post_session(user_id)
            .map(|session| principal_of(&session))
        else {
            return Ok(());
        };
        let mut pending: Vec<(ChannelInstanceId, InviteId)> = self
            .view
            .post_channels()
            .iter()
            .flat_map(|channel| {
                channel
                    .invites
                    .iter()
                    .filter(|invite| invite.target == principal)
                    .map(|invite| (channel.channel_id, invite.invite_id))
                    .collect::<Vec<_>>()
            })
            .collect();
        pending.sort_unstable();
        for (channel_id, invite_id) in pending {
            let held = self
                .index
                .edges
                .get(&home)
                .is_some_and(|standing| standing.holds_invite(channel_id, invite_id));
            if held {
                continue;
            }
            self.touch_channel(channel_id);
            if let Some(event) = self.invited_event(channel_id, invite_id, true) {
                self.emit(index, home, event);
            }
        }
        Ok(())
    }

    fn project_session_hidden(
        &mut self,
        index: u16,
        user_id: UserId,
        kind: SessionHideKind,
    ) -> Result<(), DomainError> {
        self.touched_users.insert(user_id);
        let Some(pre) = self.view.pre_session(user_id) else {
            return Ok(());
        };
        let home = pre.home_server_id;
        let Some(source) = self.source_view(user_id) else {
            return Ok(());
        };
        if let Some(account_id) = pre.account_id {
            self.touched_accounts.insert(account_id);
        }
        let resulting = self.resulting_revision();
        let departed: Vec<(ChannelInstanceId, Revision)> = pre
            .joined_channels
            .iter()
            .map(|channel_id| (*channel_id, resulting))
            .collect();
        for (channel_id, _) in &departed {
            self.touch_channel(*channel_id);
        }
        let reason = if kind == SessionHideKind::ClientQuit {
            self.context.reason.clone()
        } else {
            kind.generic_reason().to_owned()
        };
        let mut recipients: BTreeMap<ServerId, Vec<(ChannelInstanceId, Revision)>> =
            BTreeMap::new();
        recipients.insert(home, departed.clone());
        for (channel_id, revision) in &departed {
            for edge in self.pre_member_edges(*channel_id) {
                if edge == home {
                    continue;
                }
                recipients
                    .entry(edge)
                    .or_default()
                    .push((*channel_id, *revision));
            }
        }
        for edge in self.view.monitor_edges(&source.nickname) {
            recipients.entry(edge).or_default();
        }
        for (edge, mut channels) in recipients {
            channels.sort_unstable();
            channels.dedup();
            self.emit(
                index,
                edge,
                ProjectedEvent::SessionHidden {
                    source: source.clone(),
                    last_revision: pre.revision,
                    kind,
                    channels,
                    reason: reason.clone(),
                },
            );
        }
        let principal = pre
            .account_id
            .map_or(Principal::Guest(user_id), Principal::Account);
        self.project_principal_invites_hidden(index, principal, home);
        Ok(())
    }

    /// Removes this edge's invite copies for a principal that no longer has a
    /// session on the edge.
    fn project_principal_invites_hidden(
        &mut self,
        index: u16,
        principal: Principal,
        home: ServerId,
    ) {
        if self.hosting_edges(principal).contains(&home) {
            return;
        }
        let Some(standing) = self.index.edges.get(&home) else {
            return;
        };
        let copies: Vec<(ChannelInstanceId, InviteId)> = standing
            .invites
            .iter()
            .filter(|(channel_id, invite_id)| {
                self.invite_targets(*channel_id, *invite_id, principal)
            })
            .copied()
            .collect();
        let resulting = self.resulting_revision();
        for (channel_id, invite_id) in copies {
            self.touch_channel(channel_id);
            self.emit(
                index,
                home,
                ProjectedEvent::InviteRemoved {
                    channel_id,
                    invite_id,
                    resulting_revision: resulting,
                    kind: InviteRemovalKind::ProjectionHidden,
                },
            );
        }
    }

    /// Whether the invite, before or after apply, targets the principal.
    fn invite_targets(
        &self,
        channel_id: ChannelInstanceId,
        invite_id: InviteId,
        principal: Principal,
    ) -> bool {
        let post = self.view.post_channel(channel_id).is_some_and(|channel| {
            channel
                .invites
                .iter()
                .any(|invite| invite.invite_id == invite_id && invite.target == principal)
        });
        post || self.view.pre_channel(channel_id).is_some_and(|channel| {
            channel
                .invites
                .iter()
                .any(|invite| invite.invite_id == invite_id && invite.target == principal)
        })
    }

    fn project_account_sessions_gone(
        &mut self,
        index: u16,
        account_id: AccountId,
        kind: SessionHideKind,
    ) -> Result<(), DomainError> {
        self.touched_accounts.insert(account_id);
        let gone: Vec<UserId> = self
            .view
            .base
            .session_user_ids()
            .filter(|user| {
                self.view
                    .pre_session(*user)
                    .is_some_and(|session| session.account_id == Some(account_id))
                    && self.view.post_session(*user).is_none()
            })
            .collect();
        for user_id in gone {
            self.project_session_hidden(index, user_id, kind)?;
        }
        Ok(())
    }

    fn project_nickname_changed(&mut self, index: u16, user_id: UserId) -> Result<(), DomainError> {
        self.touched_users.insert(user_id);
        let Some(old) = self
            .view
            .pre_session(user_id)
            .map(|session| session.nickname)
        else {
            return Ok(());
        };
        let Some(home) = self.home_of(user_id) else {
            return Ok(());
        };
        let Some(new_nickname) = self
            .view
            .post_session(user_id)
            .map(|session| session.nickname.clone())
        else {
            return Ok(());
        };
        let mut edges = self.shared_edges(user_id);
        edges.extend(self.view.monitor_edges(&old));
        edges.extend(self.view.monitor_edges(&new_nickname));
        edges.insert(home);
        for edge in edges {
            if let Some(view) = self.event_view(user_id, edge) {
                self.emit(
                    index,
                    edge,
                    ProjectedEvent::NicknameChanged {
                        old_nickname: old.clone(),
                        view,
                    },
                );
            }
        }
        Ok(())
    }

    fn project_away_changed(&mut self, index: u16, user_id: UserId) -> Result<(), DomainError> {
        self.touched_users.insert(user_id);
        let Some(home) = self.home_of(user_id) else {
            return Ok(());
        };
        let away = self
            .view
            .post_session(user_id)
            .and_then(|session| session.away.clone());
        let mut edges = self.shared_edges(user_id);
        edges.insert(home);
        for edge in edges {
            if let Some(view) = self.event_view(user_id, edge) {
                self.emit(
                    index,
                    edge,
                    ProjectedEvent::AwayChanged {
                        view,
                        away: away.clone(),
                    },
                );
            }
        }
        Ok(())
    }

    fn project_user_modes_changed(
        &mut self,
        index: u16,
        user_id: UserId,
    ) -> Result<(), DomainError> {
        self.touched_users.insert(user_id);
        if let (Some(home), Some(record)) = (self.home_of(user_id), self.session_record(user_id)) {
            self.emit(index, home, ProjectedEvent::UserModesChanged(record));
        }
        Ok(())
    }

    fn project_display_name_changed(
        &mut self,
        index: u16,
        user_id: UserId,
    ) -> Result<(), DomainError> {
        self.touched_users.insert(user_id);
        let Some(home) = self.home_of(user_id) else {
            return Ok(());
        };
        let Some(display_name) = self
            .view
            .post_session(user_id)
            .map(|session| session.display_name.clone())
        else {
            return Ok(());
        };
        let mut edges = self.shared_edges(user_id);
        edges.insert(home);
        for edge in edges {
            if let Some(view) = self.event_view(user_id, edge) {
                self.emit(
                    index,
                    edge,
                    ProjectedEvent::DisplayNameChanged {
                        view,
                        display_name: display_name.clone(),
                    },
                );
            }
        }
        Ok(())
    }

    fn membership_view(
        &self,
        channel_id: ChannelInstanceId,
        user_id: UserId,
    ) -> Option<MembershipView> {
        let channel = self.view.post_channel(channel_id)?;
        let membership = channel
            .memberships
            .iter()
            .find(|membership| membership.user_id == user_id)?;
        let source = self.source_view(user_id)?;
        Some(MembershipView {
            membership: MembershipRecord {
                channel_id,
                user_id,
                role: membership.effective_role,
                membership_revision: membership.membership_revision,
                joined_at: membership.joined_at,
            },
            source,
        })
    }

    fn project_joined(
        &mut self,
        index: u16,
        channel_id: ChannelInstanceId,
        user_id: UserId,
    ) -> Result<(), DomainError> {
        self.touched_users.insert(user_id);
        self.touch_channel(channel_id);
        let Some(view) = self.membership_view(channel_id, user_id) else {
            return Ok(());
        };
        let Some(session) = self.view.post_session(user_id).map(Cow::into_owned) else {
            return Ok(());
        };
        let home = session.home_server_id;
        let principal = principal_of(&session);
        let mut edges = self.member_edges(channel_id);
        edges.insert(home);
        for edge in edges {
            self.emit(
                index,
                edge,
                ProjectedEvent::MemberJoined {
                    view: view.clone(),
                    home_session_revision: (edge == home).then_some(session.revision),
                    display_name: session.display_name.clone(),
                },
            );
        }
        let consumed: Vec<InviteId> = self
            .view
            .pre_channel(channel_id)
            .map(|pre| {
                pre.invites
                    .iter()
                    .filter(|invite| {
                        invite.target == principal
                            && !self.view.post_channel(channel_id).is_some_and(|post| {
                                post.invites
                                    .iter()
                                    .any(|current| current.invite_id == invite.invite_id)
                            })
                    })
                    .map(|invite| invite.invite_id)
                    .collect()
            })
            .unwrap_or_default();
        for invite_id in consumed {
            self.project_invite_removed(index, channel_id, invite_id, InviteRemovalKind::Consumed);
        }
        Ok(())
    }

    fn project_parted(
        &mut self,
        index: u16,
        channel_id: ChannelInstanceId,
        user_id: UserId,
    ) -> Result<(), DomainError> {
        self.touched_users.insert(user_id);
        self.touch_channel(channel_id);
        if self.view.pre_channel(channel_id).is_none() {
            return Ok(());
        }
        let Some(source) = self.source_view(user_id) else {
            return Ok(());
        };
        let Some(home) = self.home_of(user_id) else {
            return Ok(());
        };
        let home_revision = self
            .view
            .post_session(user_id)
            .map(|session| session.revision);
        let resulting = self.resulting_revision();
        let mut edges = self.member_edges(channel_id);
        edges.extend(self.pre_member_edges(channel_id));
        edges.insert(home);
        for edge in edges {
            let home_session_revision = (edge == home).then_some(home_revision).flatten();
            let event = if self.context.kicked {
                ProjectedEvent::Kicked {
                    channel_id,
                    actor: self.actor_view(),
                    target: source.clone(),
                    resulting_revision: resulting,
                    target_home_session_revision: home_session_revision,
                    reason: self.context.reason.clone(),
                }
            } else {
                ProjectedEvent::MemberParted {
                    channel_id,
                    source: source.clone(),
                    resulting_revision: resulting,
                    home_session_revision,
                    reason: self.context.reason.clone(),
                }
            };
            self.emit(index, edge, event);
        }
        Ok(())
    }

    fn project_channel_destroyed(&mut self, index: u16, channel_id: ChannelInstanceId) {
        self.touch_channel(channel_id);
        let holders: Vec<ServerId> = self
            .index
            .edges
            .iter()
            .filter(|(_, standing)| standing.holds_channel(channel_id))
            .map(|(edge, _)| *edge)
            .collect();
        let final_revision = self.resulting_revision();
        for edge in holders {
            self.emit(
                index,
                edge,
                ProjectedEvent::ChannelDestroyed {
                    channel_id,
                    final_revision,
                },
            );
        }
    }

    fn project_topic_changed(
        &mut self,
        index: u16,
        channel_id: ChannelInstanceId,
        _message_id: MessageId,
    ) -> Result<(), DomainError> {
        self.touch_channel(channel_id);
        let Some(channel) = self.view.post_channel(channel_id).map(Cow::into_owned) else {
            return Ok(());
        };
        let topic = channel
            .topic
            .as_ref()
            .map(|topic| (topic.text.clone(), topic.set_at, topic.message_id));
        let Some(actor) = self
            .context
            .actor
            .or_else(|| channel.topic.as_ref().map(|topic| topic.setter))
            .and_then(|actor| self.source_view(actor))
        else {
            return Ok(());
        };
        let resulting = self.resulting_revision();
        for edge in self.member_edges(channel_id) {
            self.emit(
                index,
                edge,
                ProjectedEvent::TopicChanged {
                    channel_id,
                    resulting_revision: resulting,
                    actor: actor.clone(),
                    topic: topic.clone(),
                },
            );
        }
        Ok(())
    }

    fn project_modes_changed(
        &mut self,
        index: u16,
        channel_id: ChannelInstanceId,
    ) -> Result<(), DomainError> {
        self.touch_channel(channel_id);
        let (Some(pre), Some(post)) = (
            self.view.pre_channel(channel_id),
            self.view.post_channel(channel_id).map(Cow::into_owned),
        ) else {
            return Ok(());
        };
        let changes = self.mode_changes(&pre, &post)?;
        if changes.is_empty() {
            return Ok(());
        }
        let resulting = self.resulting_revision();
        let actor = self.actor_view();
        for edge in self.member_edges(channel_id) {
            self.emit(
                index,
                edge,
                ProjectedEvent::ChannelModesChanged {
                    channel_id,
                    resulting_revision: resulting,
                    actor: actor.clone(),
                    changes: changes.clone(),
                },
            );
        }
        Ok(())
    }

    fn mode_changes(
        &self,
        pre: &DurableChannel,
        post: &DurableChannel,
    ) -> Result<Vec<ProjectedModeChange>, DomainError> {
        let mut changes = Vec::new();
        self.diff_list(
            post.channel_id,
            MODE_CODE_BAN,
            &pre.bans,
            &post.bans,
            &mut changes,
        )?;
        self.diff_list(
            post.channel_id,
            MODE_CODE_EXCEPTION,
            &pre.exceptions,
            &post.exceptions,
            &mut changes,
        )?;
        self.diff_list(
            post.channel_id,
            MODE_CODE_INVITE_EXCEPTION,
            &pre.invite_exceptions,
            &post.invite_exceptions,
            &mut changes,
        )?;
        scalar_mode_changes(pre, post, &mut changes);
        self.prefix_mode_changes(pre, post, &mut changes);
        Ok(changes)
    }

    fn diff_list(
        &self,
        channel_id: ChannelInstanceId,
        code: u16,
        before: &[DurableListEntry],
        after: &[DurableListEntry],
        changes: &mut Vec<ProjectedModeChange>,
    ) -> Result<(), DomainError> {
        let absent = |entries: &[DurableListEntry], entry: &DurableListEntry| {
            !entries
                .iter()
                .any(|candidate| candidate.entry_id == entry.entry_id)
        };
        for entry in before.iter().filter(|entry| absent(after, entry)) {
            changes.push(ProjectedModeChange::List {
                direction: ModeDirection::Remove,
                entry: self.list_entry(channel_id, code, entry)?,
            });
        }
        for entry in after.iter().filter(|entry| absent(before, entry)) {
            changes.push(ProjectedModeChange::List {
                direction: ModeDirection::Add,
                entry: self.list_entry(channel_id, code, entry)?,
            });
        }
        Ok(())
    }

    fn prefix_mode_changes(
        &self,
        pre: &DurableChannel,
        post: &DurableChannel,
        changes: &mut Vec<ProjectedModeChange>,
    ) {
        for membership in &pre.memberships {
            let Some(after) = post
                .memberships
                .iter()
                .find(|candidate| candidate.user_id == membership.user_id)
            else {
                continue;
            };
            if after.session_role == membership.session_role {
                continue;
            }
            let Some(view) = self.membership_view(post.channel_id, membership.user_id) else {
                continue;
            };
            let (direction, code) = if after.session_role > membership.session_role {
                (ModeDirection::Add, prefix_code(after.session_role))
            } else {
                (ModeDirection::Remove, prefix_code(membership.session_role))
            };
            if let Some(mode_code) = code {
                changes.push(ProjectedModeChange::Prefix {
                    direction,
                    mode_code,
                    view,
                });
            }
        }
    }

    fn list_entry(
        &self,
        channel_id: ChannelInstanceId,
        mode_code: u16,
        entry: &DurableListEntry,
    ) -> Result<ModeListEntryRecord, DomainError> {
        let setter = match entry.setter {
            Principal::Guest(user_id) => self.source_view(user_id),
            Principal::Account(account_id) => self
                .view
                .post_sessions()
                .iter()
                .find(|session| session.account_id == Some(account_id))
                .and_then(|session| self.source_view(session.user_id)),
        }
        .ok_or(DomainError::NotFound)?;
        Ok(ModeListEntryRecord {
            channel_id,
            mode_code,
            entry_id: entry.entry_id,
            mask: entry.mask.clone(),
            setter,
            created_at: entry.created_at,
            expires_at: None,
        })
    }

    fn project_recompute(
        &mut self,
        index: u16,
        channel_id: ChannelInstanceId,
        account_id: AccountId,
    ) -> Result<(), DomainError> {
        self.touch_channel(channel_id);
        self.touched_accounts.insert(account_id);
        let Some(channel) = self.view.post_channel(channel_id).map(Cow::into_owned) else {
            return Ok(());
        };
        let memberships: Vec<MembershipView> = channel
            .memberships
            .iter()
            .filter(|membership| membership.account_id == Some(account_id))
            .filter_map(|membership| self.membership_view(channel_id, membership.user_id))
            .collect();
        if memberships.is_empty() {
            return Ok(());
        }
        let resulting = self.resulting_revision();
        let actor = self.actor_view();
        for edge in self.member_edges(channel_id) {
            self.emit(
                index,
                edge,
                ProjectedEvent::ChannelMembershipsRecomputed {
                    channel_id,
                    resulting_revision: resulting,
                    actor: actor.clone(),
                    memberships: memberships.clone(),
                },
            );
        }
        Ok(())
    }

    fn project_message(
        &mut self,
        index: u16,
        message_id: MessageId,
        sender: UserId,
    ) -> Result<(), DomainError> {
        self.touched_users.insert(sender);
        let Some(batch) = self.plan.message_batch() else {
            return Ok(());
        };
        let Some(route) = batch
            .routes()
            .iter()
            .find(|route| route.message_id() == message_id)
        else {
            return Ok(());
        };
        let Some(sender_view) = self.source_view(sender) else {
            return Ok(());
        };
        let body = match batch.kind() {
            MessageKind::Tagmsg => String::new(),
            MessageKind::Privmsg | MessageKind::Notice => batch.body().unwrap_or("").to_owned(),
        };
        let Some(delivery) = self.resolve_delivery(route, sender)? else {
            return Ok(());
        };
        for edge in delivery.edges {
            self.emit(
                index,
                edge,
                ProjectedEvent::MessageDelivered(DeliveredMessageRecord {
                    message_id,
                    kind: batch.kind(),
                    target: delivery.target,
                    sender: sender_view.clone(),
                    target_revision: delivery.target_revision,
                    channel_event_sequence: delivery.sequence,
                    received_unix_milliseconds: self.context.received_unix_milliseconds,
                    tags: self.context.client_tags.clone(),
                    body: body.clone(),
                }),
            );
        }
        Ok(())
    }

    /// Resolves one accepted route into its target, revision, sequence, and
    /// recipient edges, or `None` when the target does not federate.
    fn resolve_delivery(
        &self,
        route: &crate::MessageRoute,
        sender: UserId,
    ) -> Result<Option<ResolvedDelivery>, DomainError> {
        match route.target() {
            ResolvedMessageTarget::Channel(channel_id) => {
                let Some(channel) = self.view.post_channel(channel_id) else {
                    return Ok(None);
                };
                let edges = route
                    .recipients()
                    .iter()
                    .filter_map(|user| self.home_of(user))
                    .collect();
                Ok(Some(ResolvedDelivery {
                    target: DeliveryTarget::Channel(channel_id),
                    target_revision: channel.revision,
                    sequence: self.resulting_revision().get(),
                    edges,
                }))
            }
            ResolvedMessageTarget::User(user_id) => {
                let mut edges = BTreeSet::new();
                edges.extend(self.home_of(sender));
                edges.extend(self.home_of(user_id));
                // A direct message binds to the recipient's session revision
                // at the committed state, so the edge can check it applied to
                // the session it knows.
                let target_revision = self
                    .view
                    .post_session(user_id)
                    .map(|session| session.revision)
                    .or_else(|| {
                        self.view
                            .pre_session(user_id)
                            .map(|session| session.revision)
                    })
                    .ok_or(DomainError::NotFound)?;
                Ok(Some(ResolvedDelivery {
                    target: DeliveryTarget::User(user_id),
                    target_revision,
                    sequence: 0,
                    edges,
                }))
            }
        }
    }

    fn invited_event(
        &self,
        channel_id: ChannelInstanceId,
        invite_id: InviteId,
        with_projection: bool,
    ) -> Option<ProjectedEvent> {
        let channel = self.view.post_channel(channel_id)?;
        let invite = channel
            .invites
            .iter()
            .find(|invite| invite.invite_id == invite_id)?;
        let inviter = self.source_view(invite.inviter)?;
        let named_target_user = match invite.target {
            Principal::Guest(user_id) => Some(user_id),
            Principal::Account(account_id) => self.context.named_target.or_else(|| {
                self.view
                    .post_sessions()
                    .iter()
                    .find(|session| session.account_id == Some(account_id))
                    .map(|session| session.user_id)
            }),
        }?;
        let named_target = self.source_view(named_target_user)?;
        let local_projection = with_projection.then_some(InviteRecord {
            channel_id,
            invite_id,
            target: invite.target,
            inviter_user_id: invite.inviter,
            creation_revision: invite.creation_revision,
            expires_at: invite.expires_at_utc,
        });
        Some(ProjectedEvent::Invited {
            channel_id,
            invite_id,
            resulting_revision: channel.revision,
            local_projection,
            inviter,
            named_target,
        })
    }

    fn project_invite_created(
        &mut self,
        index: u16,
        channel_id: ChannelInstanceId,
        invite_id: InviteId,
    ) -> Result<(), DomainError> {
        self.touch_channel(channel_id);
        let Some(target) = self.view.post_channel(channel_id).and_then(|channel| {
            channel
                .invites
                .iter()
                .find(|invite| invite.invite_id == invite_id)
                .map(|invite| invite.target)
        }) else {
            return Ok(());
        };
        let target_edges = self.hosting_edges(target);
        for edge in &target_edges {
            if let Some(event) = self.invited_event(channel_id, invite_id, true) {
                self.emit(index, *edge, event);
            }
        }
        for edge in self.member_edges(channel_id) {
            if target_edges.contains(&edge) {
                continue;
            }
            if let Some(event) = self.invited_event(channel_id, invite_id, false) {
                self.emit(index, edge, event);
            }
        }
        Ok(())
    }

    fn project_invite_removed(
        &mut self,
        index: u16,
        channel_id: ChannelInstanceId,
        invite_id: InviteId,
        kind: InviteRemovalKind,
    ) {
        let holders: Vec<ServerId> = self
            .index
            .edges
            .iter()
            .filter(|(_, standing)| standing.holds_invite(channel_id, invite_id))
            .map(|(edge, _)| *edge)
            .collect();
        let resulting = self.resulting_revision();
        for edge in holders {
            self.emit(
                index,
                edge,
                ProjectedEvent::InviteRemoved {
                    channel_id,
                    invite_id,
                    resulting_revision: resulting,
                    kind,
                },
            );
        }
    }

    fn account_record(&self, account_id: AccountId) -> Option<AccountRecord> {
        let account = self.view.post_account(account_id)?;
        Some(AccountRecord {
            account_id,
            account_session_generation: account.session_generation,
            account_revision: account.revision,
        })
    }

    fn project_account_updated(
        &mut self,
        index: u16,
        account_id: AccountId,
    ) -> Result<(), DomainError> {
        self.touched_accounts.insert(account_id);
        let Some(record) = self.account_record(account_id) else {
            return Ok(());
        };
        let sessions: Vec<UserId> = self
            .view
            .post_sessions()
            .iter()
            .filter(|session| session.account_id == Some(account_id))
            .map(|session| session.user_id)
            .collect();
        let hosting: BTreeSet<ServerId> = sessions
            .iter()
            .filter_map(|user| self.home_of(*user))
            .collect();
        for edge in &hosting {
            self.emit(index, *edge, ProjectedEvent::AccountStateChanged(record));
        }
        let label_changed = self
            .view
            .pre_account(account_id)
            .map(|account| account.label)
            != self
                .view
                .post_account(account_id)
                .map(|account| account.label.clone());
        if !label_changed {
            return Ok(());
        }
        for user_id in sessions {
            self.touched_users.insert(user_id);
            let mut edges = self.shared_edges(user_id);
            edges.extend(self.home_of(user_id));
            for edge in edges {
                if let Some(view) = self.event_view(user_id, edge) {
                    self.emit(index, edge, ProjectedEvent::AccountLabelChanged(view));
                }
            }
        }
        Ok(())
    }

    fn project_policy_changed(
        &mut self,
        index: u16,
        channel_id: ChannelInstanceId,
    ) -> Result<(), DomainError> {
        self.touch_channel(channel_id);
        let Some(detail) = self.detail(channel_id) else {
            return Ok(());
        };
        let holders: Vec<ServerId> = self
            .index
            .edges
            .iter()
            .filter(|(_, standing)| standing.holds_channel(channel_id))
            .map(|(edge, _)| *edge)
            .collect();
        for edge in holders {
            self.emit(
                index,
                edge,
                ProjectedEvent::ChannelPolicyChanged(detail.clone()),
            );
        }
        Ok(())
    }

    /// Adds entitlement transitions, orders every copy, and computes the
    /// standing deltas for each touched edge.
    fn finish(mut self) -> Result<MutationProjection, DomainError> {
        self.project_revision_carriers();
        self.project_entitlement_transitions();
        let emissions = std::mem::take(&mut self.emissions);
        let mut deltas = group_emissions(emissions);
        let touched_edges: BTreeSet<ServerId> = deltas
            .keys()
            .copied()
            .chain(self.touched_edges())
            .filter(|edge| *edge != self.index.local_server_id)
            .collect();
        for edge in touched_edges {
            let (upserts, removals) = self.standing_delta(edge);
            if upserts.is_empty() && removals.is_empty() && !deltas.contains_key(&edge) {
                continue;
            }
            let delta = deltas.entry(edge).or_insert_with(|| EdgeDelta::empty(edge));
            delta.upserts = upserts;
            delta.removals = removals;
        }
        Ok(MutationProjection {
            edges: deltas.into_values().collect(),
        })
    }

    /// Sends the complete resulting detail to every edge that keeps a channel
    /// this plan advanced but receives no copy carrying that revision: an
    /// edge entitled only by an invite, or a member edge of a channel whose
    /// invite was removed. A delivered message binds to the installed
    /// revision, so an edge left behind would refuse the next one.
    fn project_revision_carriers(&mut self) {
        let advanced: Vec<ChannelInstanceId> = self
            .view
            .channels
            .iter()
            .filter(|(channel_id, post)| {
                let pre = self.view.pre_channel(**channel_id);
                pre.zip(post.as_ref())
                    .is_some_and(|(pre, post)| pre.revision != post.revision)
            })
            .map(|(channel_id, _)| *channel_id)
            .collect();
        let edges: Vec<ServerId> = self.index.edges.keys().copied().collect();
        for channel_id in advanced {
            for edge in &edges {
                self.project_revision_carrier(*edge, channel_id);
            }
        }
    }

    fn project_revision_carrier(&mut self, edge: ServerId, channel_id: ChannelInstanceId) {
        if !self.entitled_before(edge, channel_id) {
            return;
        }
        self.touch_channel(channel_id);
        let carried = self
            .emissions
            .iter()
            .any(|emission| emission.edge == edge && advances_channel(&emission.event, channel_id));
        if carried || !self.entitled_after(edge, channel_id) {
            return;
        }
        if let Some(detail) = self.detail(channel_id) {
            let index = self.last_index_for(channel_id);
            self.emit(index, edge, ProjectedEvent::ChannelPolicyChanged(detail));
        }
    }

    /// Every edge whose standing may change: homes of touched users before or
    /// after, holders of touched channels and accounts.
    fn touched_edges(&self) -> BTreeSet<ServerId> {
        let mut edges = BTreeSet::new();
        for user in &self.touched_users {
            edges.extend(self.home_of(*user));
            edges.extend(
                self.view
                    .pre_session(*user)
                    .map(|session| session.home_server_id),
            );
        }
        for (edge, standing) in &self.index.edges {
            if self
                .touched_channels
                .iter()
                .any(|channel| standing.holds_channel(*channel))
                || self
                    .touched_accounts
                    .iter()
                    .any(|account| standing.holds_account(*account))
            {
                edges.insert(*edge);
            }
        }
        for channel_id in &self.touched_channels {
            edges.extend(self.member_edges(*channel_id));
            if let Some(channel) = self.view.post_channel(*channel_id) {
                for invite in &channel.invites {
                    edges.extend(self.hosting_edges(invite.target));
                }
            }
        }
        for account in &self.touched_accounts {
            edges.extend(self.hosting_edges(Principal::Account(*account)));
        }
        edges
    }

    fn project_entitlement_transitions(&mut self) {
        let channels: Vec<ChannelInstanceId> = self.touched_channels.iter().copied().collect();
        let mut edges: BTreeSet<ServerId> = self.index.edges.keys().copied().collect();
        edges.extend(self.touched_edges());
        let announced: BTreeSet<ChannelInstanceId> = self
            .plan
            .events()
            .iter()
            .filter_map(|event| match event {
                DomainEvent::ChannelDestroyed(channel) => Some(*channel),
                _ => None,
            })
            .collect();
        for channel_id in channels {
            let destroyed = self.view.pre_channel(channel_id).is_some()
                && self.view.post_channel(channel_id).is_none();
            if destroyed && !announced.contains(&channel_id) {
                let index = self.last_index_for(channel_id);
                self.project_channel_destroyed(index, channel_id);
                continue;
            }
            for edge in &edges {
                self.project_entitlement_transition(
                    *edge,
                    channel_id,
                    announced.contains(&channel_id),
                );
            }
        }
    }

    fn project_entitlement_transition(
        &mut self,
        edge: ServerId,
        channel_id: ChannelInstanceId,
        announced_destroyed: bool,
    ) {
        let before = self.entitled_before(edge, channel_id);
        let after = self.entitled_after(edge, channel_id);
        if !before && after {
            if let Some(detail) = self.detail(channel_id) {
                let index = self.first_index_for(channel_id);
                self.emit(index, edge, ProjectedEvent::ChannelVisible(detail));
            }
        } else if before && !after && !announced_destroyed {
            let index = self.last_index_for(channel_id);
            let last_revision = self.resulting_revision();
            self.emit(
                index,
                edge,
                ProjectedEvent::ChannelHidden {
                    channel_id,
                    last_revision,
                },
            );
        }
    }

    fn indices_for(&self, channel_id: ChannelInstanceId) -> impl Iterator<Item = u16> + '_ {
        self.emissions
            .iter()
            .filter(move |emission| {
                emission
                    .event
                    .subject_key()
                    .starts_with(channel_id.as_bytes())
            })
            .map(|emission| emission.target_index)
    }

    fn first_index_for(&self, channel_id: ChannelInstanceId) -> u16 {
        self.indices_for(channel_id).min().unwrap_or(0)
    }

    fn last_index_for(&self, channel_id: ChannelInstanceId) -> u16 {
        self.indices_for(channel_id).max().unwrap_or(u16::MAX)
    }

    /// Computes the standing upserts and removals for one edge from the
    /// overlay restricted to touched entities.
    fn standing_delta(&self, edge: ServerId) -> (Vec<ProjectionRecord>, Vec<ProjectionKey>) {
        let mut delta = StandingDelta::default();
        self.session_standing(edge, &mut delta);
        for channel_id in &self.touched_channels {
            let entitled = self.entitled_after(edge, *channel_id);
            self.detail_standing(edge, *channel_id, entitled, &mut delta);
            self.membership_standing(edge, *channel_id, entitled, &mut delta);
            self.invite_standing(edge, *channel_id, entitled, &mut delta);
        }
        self.account_standing(edge, &mut delta);
        (delta.upserts, delta.removals)
    }

    fn session_standing(&self, edge: ServerId, delta: &mut StandingDelta) {
        let standing = self.index.edges.get(&edge);
        for user_id in &self.touched_users {
            let was_home = standing.is_some_and(|standing| standing.holds_session(*user_id));
            match self.view.post_session(*user_id) {
                Some(session) if session.home_server_id == edge => {
                    let label = self.label_of(session.account_id);
                    delta
                        .upserts
                        .push(ProjectionRecord::Session(session_record_from(
                            &session, label,
                        )));
                }
                _ if was_home => delta.removals.push(ProjectionKey::session(*user_id)),
                _ => {}
            }
        }
    }

    fn detail_standing(
        &self,
        edge: ServerId,
        channel_id: ChannelInstanceId,
        entitled: bool,
        delta: &mut StandingDelta,
    ) {
        match self.detail(channel_id) {
            Some(detail) if entitled => delta.upserts.push(ProjectionRecord::ChannelDetail(detail)),
            _ if self.entitled_before(edge, channel_id) => {
                delta
                    .removals
                    .push(ProjectionKey::channel_detail(channel_id));
            }
            _ => {}
        }
    }

    fn membership_standing(
        &self,
        edge: ServerId,
        channel_id: ChannelInstanceId,
        entitled: bool,
        delta: &mut StandingDelta,
    ) {
        let standing = self.index.edges.get(&edge);
        let post_users: BTreeSet<UserId> = self
            .view
            .post_channel(channel_id)
            .map(|channel| {
                channel
                    .memberships
                    .iter()
                    .map(|membership| membership.user_id)
                    .collect()
            })
            .unwrap_or_default();
        let mut considered: BTreeSet<UserId> = self.touched_users.clone();
        if let Some(standing) = standing {
            considered.extend(
                standing
                    .memberships
                    .iter()
                    .filter(|(channel, _)| *channel == channel_id)
                    .map(|(_, user)| *user),
            );
        }
        for user_id in considered {
            let local = self.home_of(user_id) == Some(edge);
            let member = post_users.contains(&user_id) && entitled;
            let held = standing
                .is_some_and(|standing| standing.memberships.contains(&(channel_id, user_id)));
            if local && member {
                if let Some(view) = self.membership_view(channel_id, user_id) {
                    delta
                        .upserts
                        .push(ProjectionRecord::Membership(view.membership));
                }
            } else if held {
                delta
                    .removals
                    .push(ProjectionKey::membership(channel_id, user_id));
            }
        }
    }

    fn invite_standing(
        &self,
        edge: ServerId,
        channel_id: ChannelInstanceId,
        entitled: bool,
        delta: &mut StandingDelta,
    ) {
        let post_invites = if entitled {
            self.hosted_invites(edge, channel_id)
        } else {
            BTreeMap::new()
        };
        for record in post_invites.values() {
            delta.upserts.push(ProjectionRecord::Invite(*record));
        }
        if let Some(standing) = self.index.edges.get(&edge) {
            for (channel, invite_id) in &standing.invites {
                if *channel == channel_id && !post_invites.contains_key(invite_id) {
                    delta
                        .removals
                        .push(ProjectionKey::invite(channel_id, *invite_id));
                }
            }
        }
    }

    /// The channel's invites whose target the edge hosts after apply.
    fn hosted_invites(
        &self,
        edge: ServerId,
        channel_id: ChannelInstanceId,
    ) -> BTreeMap<InviteId, InviteRecord> {
        let Some(channel) = self.view.post_channel(channel_id) else {
            return BTreeMap::new();
        };
        channel
            .invites
            .iter()
            .filter(|invite| self.hosting_edges(invite.target).contains(&edge))
            .map(|invite| {
                (
                    invite.invite_id,
                    InviteRecord {
                        channel_id,
                        invite_id: invite.invite_id,
                        target: invite.target,
                        inviter_user_id: invite.inviter,
                        creation_revision: invite.creation_revision,
                        expires_at: invite.expires_at_utc,
                    },
                )
            })
            .collect()
    }

    fn account_standing(&self, edge: ServerId, delta: &mut StandingDelta) {
        let standing = self.index.edges.get(&edge);
        for account_id in &self.touched_accounts {
            let hosting = self
                .hosting_edges(Principal::Account(*account_id))
                .contains(&edge);
            let held = standing.is_some_and(|standing| standing.holds_account(*account_id));
            match self.account_record(*account_id) {
                Some(record) if hosting => delta.upserts.push(ProjectionRecord::Account(record)),
                _ if held => delta.removals.push(ProjectionKey::account(*account_id)),
                _ => {}
            }
        }
    }
}

/// Orders copies by target index, phase, edge, and subject key, then groups
/// them per edge, dropping a visible/hidden copy repeated back to back.
fn group_emissions(mut emissions: Vec<Emission>) -> BTreeMap<ServerId, EdgeDelta> {
    emissions.sort_by(|left, right| {
        left.target_index
            .cmp(&right.target_index)
            .then_with(|| left.event.phase().cmp(&right.event.phase()))
            .then_with(|| left.edge.as_bytes().cmp(right.edge.as_bytes()))
            .then_with(|| left.event.subject_key().cmp(&right.event.subject_key()))
    });
    let mut deltas: BTreeMap<ServerId, EdgeDelta> = BTreeMap::new();
    for emission in emissions {
        let delta = deltas
            .entry(emission.edge)
            .or_insert_with(|| EdgeDelta::empty(emission.edge));
        let repeated_transition = delta.events.last() == Some(&emission.event)
            && matches!(
                emission.event,
                ProjectedEvent::ChannelVisible(_) | ProjectedEvent::ChannelHidden { .. }
            );
        if !repeated_transition {
            delta.events.push(emission.event);
        }
    }
    deltas
}

/// Whether an edge applying the copy installs the channel's resulting
/// revision. A `projection_hidden` removal repeats the installed revision and
/// a channel transition belongs to an edge that does not keep the channel.
fn advances_channel(event: &ProjectedEvent, channel: ChannelInstanceId) -> bool {
    match event {
        ProjectedEvent::MemberJoined { view, .. } => view.membership.channel_id == channel,
        ProjectedEvent::SessionHidden { channels, .. } => {
            channels.iter().any(|(listed, _)| *listed == channel)
        }
        ProjectedEvent::InviteRemoved {
            channel_id, kind, ..
        } => *channel_id == channel && *kind != InviteRemovalKind::ProjectionHidden,
        ProjectedEvent::ChannelPolicyChanged(detail) => detail.channel_id == channel,
        ProjectedEvent::MemberParted { channel_id, .. }
        | ProjectedEvent::Kicked { channel_id, .. }
        | ProjectedEvent::ChannelModesChanged { channel_id, .. }
        | ProjectedEvent::TopicChanged { channel_id, .. }
        | ProjectedEvent::ChannelMembershipsRecomputed { channel_id, .. }
        | ProjectedEvent::Invited { channel_id, .. } => *channel_id == channel,
        _ => false,
    }
}

fn scalar_mode_changes(
    pre: &DurableChannel,
    post: &DurableChannel,
    changes: &mut Vec<ProjectedModeChange>,
) {
    let key_after = post.key_verifier.is_some();
    if pre.key_verifier != post.key_verifier {
        changes.push(ProjectedModeChange::Key {
            direction: direction_of(key_after),
            present: key_after,
        });
    }
    if pre.member_limit != post.member_limit {
        changes.push(ProjectedModeChange::Limit {
            direction: direction_of(post.member_limit.is_some()),
            limit: post.member_limit.map_or(0, u32::from),
        });
    }
    let before_bits = simple_mode_bits(pre.modes, pre.visibility);
    let after_bits = simple_mode_bits(post.modes, post.visibility);
    for (bit, code) in [
        (MODE_BIT_INVITE_ONLY, MODE_CODE_INVITE_ONLY),
        (MODE_BIT_MODERATED, MODE_CODE_MODERATED),
        (MODE_BIT_PRIVATE, MODE_CODE_PRIVATE),
        (MODE_BIT_SECRET, MODE_CODE_SECRET),
        (MODE_BIT_TOPIC_PROTECTED, MODE_CODE_TOPIC_PROTECTED),
    ] {
        if before_bits & bit != after_bits & bit {
            changes.push(ProjectedModeChange::Simple {
                direction: direction_of(after_bits & bit != 0),
                mode_code: code,
            });
        }
    }
}

const fn direction_of(set: bool) -> ModeDirection {
    if set {
        ModeDirection::Add
    } else {
        ModeDirection::Remove
    }
}

fn principal_of(session: &DurableSession) -> Principal {
    session
        .account_id
        .map_or(Principal::Guest(session.user_id), Principal::Account)
}

fn prefix_code(role: Role) -> Option<u16> {
    match role {
        Role::Member => None,
        Role::Voice => Some(16),
        Role::HalfOperator => Some(15),
        Role::Operator => Some(14),
        Role::Administrator => Some(13),
        Role::Owner => Some(12),
    }
}

/// Computes the B.4 simple-mode bits of one channel.
#[must_use]
pub fn simple_mode_bits(modes: crate::ChannelModes, visibility: Visibility) -> u16 {
    let mut bits = MODE_BIT_NO_EXTERNAL;
    if modes.invite_only {
        bits |= MODE_BIT_INVITE_ONLY;
    }
    if modes.moderated {
        bits |= MODE_BIT_MODERATED;
    }
    if modes.topic_protected {
        bits |= MODE_BIT_TOPIC_PROTECTED;
    }
    match visibility {
        Visibility::Listed => {}
        Visibility::Unlisted => bits |= MODE_BIT_PRIVATE,
        Visibility::Secret => bits |= MODE_BIT_SECRET,
    }
    bits
}

/// Computes the B.4 user-mode bits of one session.
#[must_use]
pub const fn user_mode_bits(operator_notices: bool) -> u16 {
    if operator_notices {
        USER_MODE_BIT_INVISIBLE | USER_MODE_BIT_WALLOPS
    } else {
        USER_MODE_BIT_INVISIBLE
    }
}

/// Builds the standing session projection of one persisted session.
#[must_use]
pub fn session_record_from(
    session: &DurableSession,
    account_label: Option<crate::AccountLabelValue>,
) -> SessionRecord {
    SessionRecord {
        session_id: session.session_id,
        user_id: session.user_id,
        home_server_id: session.home_server_id,
        session_revision: session.revision,
        account: session
            .account_id
            .map(|account| (account, session.account_session_generation)),
        nickname: session.nickname.clone(),
        display_name: session.display_name.clone(),
        public_cloak: session.public_cloak,
        account_label,
        user_mode_bits: user_mode_bits(session.operator_notices),
        away: session.away.clone(),
    }
}

/// Builds the standing channel detail of one persisted channel.
#[must_use]
pub fn channel_detail_from(channel: &DurableChannel) -> ChannelDetailRecord {
    ChannelDetailRecord {
        channel_id: channel.channel_id,
        name: channel.name.clone(),
        channel_revision: channel.revision,
        visibility: channel.visibility,
        content_policy: channel.content_policy,
        persistence: channel.persistence,
        simple_mode_bits: simple_mode_bits(channel.modes, channel.visibility),
        history: channel.history,
        e2ee_route_binding: None,
    }
}

#[cfg(test)]
#[path = "tests/projection.rs"]
mod tests;
