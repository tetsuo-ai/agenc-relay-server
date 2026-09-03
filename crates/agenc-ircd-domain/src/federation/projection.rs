//! Coordinator-side derivation of least-information events and standing
//! projection deltas for every target edge (spec 20.6, 20.8, B.4, B.5).
//!
//! The derivation is a pure function of the pre-image captured before apply,
//! the post-apply state, the apply receipt, and the coordinator's standing
//! index of what each edge already holds. It emits per-edge event copies in
//! the Section-20.6 order and the exact standing upserts and removals the
//! storage transaction must carry. Nothing here allocates identities, encodes
//! bytes, or touches a socket.

use std::collections::{BTreeMap, BTreeSet};

use agenc_ircd_types::{
    AccountId, ChannelInstanceId, InviteId, MessageId, Revision, ServerId, UserId,
};

use crate::federation::record::{
    AccountRecord, ActorView, ChannelDetailRecord, DeliveredMessageRecord, DeliveryTarget,
    InviteRecord, InviteRemovalKind, MembershipRecord, MembershipView, ModeDirection,
    ModeListEntryRecord, ProjectedEvent, ProjectedModeChange, ProjectionKey, ProjectionRecord,
    SessionEventView, SessionHideKind, SessionRecord, SourceView,
};
use crate::{
    ApplyReceipt, ChannelScope, ChannelState, DomainError, DomainEvent, DomainState,
    DurableAccount, DurableChannel, DurableListEntry, DurableSession, MessageKind, NicknameValue,
    PersistencePolicy, Principal, ResolvedMessageTarget, Role, SessionState, Visibility,
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

/// Runtime-supplied intent that the receipt alone cannot express.
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

/// Entities captured before apply so removals can still be projected.
#[derive(Default)]
pub struct PreImage {
    sessions: BTreeMap<UserId, DurableSession>,
    channels: BTreeMap<ChannelInstanceId, DurableChannel>,
    accounts: BTreeMap<AccountId, DurableAccount>,
    monitors: BTreeMap<UserId, (ServerId, Vec<NicknameValue>)>,
}

impl PreImage {
    /// Captures every entity a plan's events name, plus the channels and
    /// account of every named session, from the state before apply.
    pub fn capture(state: &DomainState, events: &[DomainEvent]) -> Self {
        let mut image = Self::default();
        for event in events {
            match event {
                DomainEvent::SessionOpened(user)
                | DomainEvent::SessionAuthorityChanged(user)
                | DomainEvent::SessionHidden(user)
                | DomainEvent::NicknameChanged(user)
                | DomainEvent::DisplayNameChanged(user)
                | DomainEvent::AwayChanged(user)
                | DomainEvent::MessageAccepted(_, user) => image.capture_session(state, *user),
                DomainEvent::Joined(channel, user) | DomainEvent::Parted(channel, user) => {
                    image.capture_session(state, *user);
                    image.capture_channel(state, *channel);
                }
                DomainEvent::ChannelCreated(channel)
                | DomainEvent::ChannelDestroyed(channel)
                | DomainEvent::TopicChanged(channel, _)
                | DomainEvent::ChannelModesChanged(channel)
                | DomainEvent::InviteCreated(channel, _)
                | DomainEvent::InviteExpired(channel, _)
                | DomainEvent::ChannelPolicyChanged(channel)
                | DomainEvent::E2eeRemovalPending(channel, _) => {
                    image.capture_channel(state, *channel);
                }
                DomainEvent::ChannelMembershipsRecomputed(channel, account) => {
                    image.capture_channel(state, *channel);
                    image.capture_account(state, *account);
                }
                DomainEvent::AccountUpdated(account)
                | DomainEvent::AccountDeleted(account)
                | DomainEvent::AccountCredentialReplaced(account) => {
                    image.capture_account(state, *account);
                }
                DomainEvent::AccountCreated(_)
                | DomainEvent::AccountDeletionChallengeStarted(_)
                | DomainEvent::AccountDeletionConfirmationRejected(_)
                | DomainEvent::SanctionRecorded(_) => {}
            }
        }
        for session in state.sessions.values() {
            let monitored: Vec<NicknameValue> =
                session.monitored_nicknames.iter().cloned().collect();
            if !monitored.is_empty() {
                image
                    .monitors
                    .insert(session.user_id, (session.home_server_id, monitored));
            }
        }
        image
    }

    fn capture_session(&mut self, state: &DomainState, user_id: UserId) {
        let Some(session) = state.durable_session(user_id) else {
            return;
        };
        for channel_id in &session.joined_channels {
            self.capture_channel(state, *channel_id);
        }
        if let Some(account_id) = session.account_id {
            self.capture_account(state, account_id);
        }
        self.sessions.insert(user_id, session);
    }

    fn capture_channel(&mut self, state: &DomainState, channel_id: ChannelInstanceId) {
        if self.channels.contains_key(&channel_id) {
            return;
        }
        if let Some(channel) = state.durable_channel(channel_id) {
            self.channels.insert(channel_id, channel);
        }
    }

    fn capture_account(&mut self, state: &DomainState, account_id: AccountId) {
        if self.accounts.contains_key(&account_id) {
            return;
        }
        if let Some(account) = state.durable_account(account_id) {
            self.accounts.insert(account_id, account);
        }
    }
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

    /// Derives every event copy and standing delta for one applied mutation.
    pub fn derive(
        &self,
        pre: &PreImage,
        post: &DomainState,
        receipt: &ApplyReceipt,
        context: &MutationContext,
    ) -> Result<MutationProjection, DomainError> {
        let mut derivation = Derivation {
            index: self,
            pre,
            post,
            receipt,
            context,
            emissions: Vec::new(),
            touched_channels: BTreeSet::new(),
            touched_users: BTreeSet::new(),
            touched_accounts: BTreeSet::new(),
        };
        for (position, event) in receipt.events().iter().enumerate() {
            let target_index = u16::try_from(position).map_err(|_| DomainError::LimitExceeded)?;
            derivation.project_event(target_index, event)?;
        }
        derivation.finish()
    }
}

struct Derivation<'a> {
    index: &'a CoordinatorProjection,
    pre: &'a PreImage,
    post: &'a DomainState,
    receipt: &'a ApplyReceipt,
    context: &'a MutationContext,
    emissions: Vec<Emission>,
    touched_channels: BTreeSet<ChannelInstanceId>,
    touched_users: BTreeSet<UserId>,
    touched_accounts: BTreeSet<AccountId>,
}

impl Derivation<'_> {
    fn resulting_revision(&self) -> Revision {
        self.receipt.revision()
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

    fn post_session(&self, user_id: UserId) -> Option<&SessionState> {
        self.post.sessions.get(&user_id)
    }

    fn home_of(&self, user_id: UserId) -> Option<ServerId> {
        self.post_session(user_id)
            .map(SessionState::home_server_id)
            .or_else(|| {
                self.pre
                    .sessions
                    .get(&user_id)
                    .map(|session| session.home_server_id)
            })
    }

    fn source_view(&self, user_id: UserId) -> Option<SourceView> {
        if let Some(session) = self.post_session(user_id) {
            return Some(source_view_of(session, self.post));
        }
        let session = self.pre.sessions.get(&user_id)?;
        Some(SourceView {
            user_id,
            nickname: session.nickname.clone(),
            public_cloak: session.public_cloak,
            account_label: session
                .account_id
                .and_then(|account| self.pre.accounts.get(&account))
                .and_then(|account| account.label.clone()),
        })
    }

    fn session_record(&self, user_id: UserId) -> Option<SessionRecord> {
        let session = self.post_session(user_id)?;
        Some(session_record_of(session, self.post))
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

    /// Edges with a session that currently monitors the nickname.
    fn monitor_edges(&self, nickname: &NicknameValue) -> BTreeSet<ServerId> {
        self.post
            .sessions
            .values()
            .filter(|session| session.monitored_nicknames.contains(nickname))
            .map(SessionState::home_server_id)
            .collect()
    }

    /// Edges with a local member in the channel after apply.
    fn member_edges(&self, channel_id: ChannelInstanceId) -> BTreeSet<ServerId> {
        let Some(channel) = self.post.channels.get(&channel_id) else {
            return BTreeSet::new();
        };
        channel
            .memberships
            .keys()
            .filter_map(|user| self.home_of(*user))
            .collect()
    }

    /// Edges with a local member in the channel before apply.
    fn pre_member_edges(&self, channel_id: ChannelInstanceId) -> BTreeSet<ServerId> {
        let Some(channel) = self.pre.channels.get(&channel_id) else {
            return BTreeSet::new();
        };
        channel
            .memberships
            .iter()
            .filter_map(|membership| self.home_of(membership.user_id))
            .collect()
    }

    /// Edges sharing at least one channel with the user after apply, plus
    /// those that shared one before apply when the user left.
    fn shared_edges(&self, user_id: UserId) -> BTreeSet<ServerId> {
        let mut edges = BTreeSet::new();
        if let Some(session) = self.post_session(user_id) {
            for channel_id in session.joined_channels() {
                edges.extend(self.member_edges(channel_id));
            }
        } else if let Some(session) = self.pre.sessions.get(&user_id) {
            for channel_id in &session.joined_channels {
                edges.extend(self.pre_member_edges(*channel_id));
            }
        }
        edges
    }

    /// Edges hosting the principal after apply.
    fn hosting_edges(&self, principal: Principal) -> BTreeSet<ServerId> {
        match principal {
            Principal::Guest(user_id) => self.home_of(user_id).into_iter().collect(),
            Principal::Account(account_id) => self
                .post
                .sessions
                .values()
                .filter(|session| session.account_id == Some(account_id))
                .map(SessionState::home_server_id)
                .collect(),
        }
    }

    fn entitled_after(&self, edge: ServerId, channel_id: ChannelInstanceId) -> bool {
        let Some(channel) = self.post.channels.get(&channel_id) else {
            return false;
        };
        if !projects(channel) {
            return false;
        }
        if channel
            .memberships
            .keys()
            .any(|user| self.home_of(*user) == Some(edge))
        {
            return true;
        }
        channel
            .invites
            .values()
            .any(|invite| self.hosting_edges(invite.target).contains(&edge))
    }

    fn entitled_before(&self, edge: ServerId, channel_id: ChannelInstanceId) -> bool {
        self.index
            .edges
            .get(&edge)
            .is_some_and(|standing| standing.holds_channel(channel_id))
    }

    fn detail(&self, channel_id: ChannelInstanceId) -> Option<ChannelDetailRecord> {
        self.post.channels.get(&channel_id).map(channel_detail_of)
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
            DomainEvent::DisplayNameChanged(user) => {
                self.project_display_name_changed(index, *user)
            }
            DomainEvent::Joined(channel, user) => self.project_joined(index, *channel, *user),
            DomainEvent::Parted(channel, user) => {
                let hidden = self.receipt.events().iter().any(
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
        for edge in self.monitor_edges(&nickname) {
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
        if let Some(previous) = self
            .pre
            .sessions
            .get(&user_id)
            .and_then(|session| session.account_id)
        {
            self.touched_accounts.insert(previous);
        }
        let Some(home) = self.home_of(user_id) else {
            return Ok(());
        };
        if let Some(view) = self.event_view(user_id, home) {
            self.emit(index, home, ProjectedEvent::SessionVisible(view));
        }
        self.project_account_hosting(index, user_id, home);
        self.reproject_account_invites(index, user_id, home)
    }

    /// Emits the account projection to the home edge when it is new there.
    fn project_account_hosting(&mut self, index: u16, user_id: UserId, home: ServerId) {
        let Some(account_id) = self
            .post_session(user_id)
            .and_then(SessionState::account_id)
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
        let principal = self.post_session(user_id).map(SessionState::principal);
        let Some(principal) = principal else {
            return Ok(());
        };
        let mut pending: Vec<(ChannelInstanceId, InviteId)> = self
            .post
            .channels
            .values()
            .filter(|channel| projects(channel))
            .flat_map(|channel| {
                channel
                    .invites
                    .values()
                    .filter(|invite| invite.target == principal)
                    .map(|invite| (channel.channel_id, invite.invite_id))
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
        let Some(pre) = self.pre.sessions.get(&user_id) else {
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
            .filter(|channel_id| self.pre.channels.contains_key(channel_id))
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
        for edge in self.monitor_edges(&source.nickname) {
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
                self.post
                    .channels
                    .get(channel_id)
                    .and_then(|channel| channel.invites.get(invite_id))
                    .is_some_and(|invite| invite.target == principal)
                    || self.pre.channels.get(channel_id).is_some_and(|channel| {
                        channel.invites.iter().any(|invite| {
                            invite.invite_id == *invite_id && invite.target == principal
                        })
                    })
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

    fn project_account_sessions_gone(
        &mut self,
        index: u16,
        account_id: AccountId,
        kind: SessionHideKind,
    ) -> Result<(), DomainError> {
        self.touched_accounts.insert(account_id);
        let gone: Vec<UserId> = self
            .pre
            .sessions
            .iter()
            .filter(|(user_id, session)| {
                session.account_id == Some(account_id) && !self.post.sessions.contains_key(user_id)
            })
            .map(|(user_id, _)| *user_id)
            .collect();
        for user_id in gone {
            self.project_session_hidden(index, user_id, kind)?;
        }
        Ok(())
    }

    fn project_nickname_changed(&mut self, index: u16, user_id: UserId) -> Result<(), DomainError> {
        self.touched_users.insert(user_id);
        let Some(old) = self
            .pre
            .sessions
            .get(&user_id)
            .map(|session| session.nickname.clone())
        else {
            return Ok(());
        };
        let Some(home) = self.home_of(user_id) else {
            return Ok(());
        };
        let Some(new_nickname) = self
            .post_session(user_id)
            .map(|session| session.nickname().clone())
        else {
            return Ok(());
        };
        let mut edges = self.shared_edges(user_id);
        edges.extend(self.monitor_edges(&old));
        edges.extend(self.monitor_edges(&new_nickname));
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
            .post_session(user_id)
            .and_then(|session| session.away().map(|text| text.as_str().to_owned()));
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
            .post_session(user_id)
            .map(|session| session.display_name().clone())
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
        let channel = self.post.channels.get(&channel_id)?;
        let membership = channel.memberships.get(&user_id)?;
        let source = self.source_view(user_id)?;
        Some(MembershipView {
            membership: MembershipRecord {
                channel_id,
                user_id,
                role: channel.effective_role(*membership),
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
        let Some(channel) = self.post.channels.get(&channel_id) else {
            return Ok(());
        };
        if !projects(channel) {
            return Ok(());
        }
        let Some(view) = self.membership_view(channel_id, user_id) else {
            return Ok(());
        };
        let Some(session) = self.post_session(user_id) else {
            return Ok(());
        };
        let home = session.home_server_id();
        let display_name = session.display_name().clone();
        let session_revision = session.revision();
        let principal = session.principal();
        let mut edges = self.member_edges(channel_id);
        edges.insert(home);
        for edge in edges {
            self.emit(
                index,
                edge,
                ProjectedEvent::MemberJoined {
                    view: view.clone(),
                    home_session_revision: (edge == home).then_some(session_revision),
                    display_name: display_name.clone(),
                },
            );
        }
        let consumed: Vec<InviteId> =
            self.pre
                .channels
                .get(&channel_id)
                .map(|pre| {
                    pre.invites
                        .iter()
                        .filter(|invite| {
                            invite.target == principal
                                && !self.post.channels.get(&channel_id).is_some_and(|post| {
                                    post.invites.contains_key(&invite.invite_id)
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
        if !self.pre.channels.contains_key(&channel_id) {
            return Ok(());
        }
        let Some(source) = self.source_view(user_id) else {
            return Ok(());
        };
        let Some(home) = self.home_of(user_id) else {
            return Ok(());
        };
        let home_revision = self.post_session(user_id).map(SessionState::revision);
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
        let Some(channel) = self.post.channels.get(&channel_id) else {
            return Ok(());
        };
        let topic = channel.topic.as_ref().map(|topic| {
            (
                topic.text.as_str().to_owned(),
                topic.set_at,
                topic.message_id,
            )
        });
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
            self.pre.channels.get(&channel_id),
            self.post.channels.get(&channel_id),
        ) else {
            return Ok(());
        };
        let changes = self.mode_changes(pre, post)?;
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
        post: &ChannelState,
    ) -> Result<Vec<ProjectedModeChange>, DomainError> {
        let mut changes = Vec::new();
        self.list_mode_changes(pre, post, &mut changes)?;
        scalar_mode_changes(pre, post, &mut changes);
        self.prefix_mode_changes(pre, post, &mut changes);
        Ok(changes)
    }

    fn list_mode_changes(
        &self,
        pre: &DurableChannel,
        post: &ChannelState,
        changes: &mut Vec<ProjectedModeChange>,
    ) -> Result<(), DomainError> {
        let post_durable = DurableChannel::from_state(post);
        let after = post_durable.as_ref();
        let channel_id = post.channel_id;
        let empty: &[DurableListEntry] = &[];
        self.diff_list(
            channel_id,
            MODE_CODE_BAN,
            &pre.bans,
            after.map_or(empty, |channel| channel.bans.as_slice()),
            changes,
        )?;
        self.diff_list(
            channel_id,
            MODE_CODE_EXCEPTION,
            &pre.exceptions,
            after.map_or(empty, |channel| channel.exceptions.as_slice()),
            changes,
        )?;
        self.diff_list(
            channel_id,
            MODE_CODE_INVITE_EXCEPTION,
            &pre.invite_exceptions,
            after.map_or(empty, |channel| channel.invite_exceptions.as_slice()),
            changes,
        )
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
        post: &ChannelState,
        changes: &mut Vec<ProjectedModeChange>,
    ) {
        for membership in &pre.memberships {
            let Some(after) = post.memberships.get(&membership.user_id) else {
                continue;
            };
            let after_role = after.role();
            if after_role == membership.session_role {
                continue;
            }
            let Some(view) = self.membership_view(post.channel_id, membership.user_id) else {
                continue;
            };
            let (direction, code) = if after_role > membership.session_role {
                (ModeDirection::Add, prefix_code(after_role))
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
                .post
                .sessions
                .values()
                .find(|session| session.account_id == Some(account_id))
                .map(|session| source_view_of(session, self.post)),
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
        let Some(channel) = self.post.channels.get(&channel_id) else {
            return Ok(());
        };
        let affected: Vec<UserId> = channel
            .memberships
            .keys()
            .copied()
            .filter(|user| {
                self.post_session(*user)
                    .is_some_and(|session| session.account_id() == Some(account_id))
            })
            .collect();
        let memberships: Vec<MembershipView> = affected
            .iter()
            .filter_map(|user| self.membership_view(channel_id, *user))
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
        let Some(batch) = self.receipt.message_batch() else {
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
                let Some(channel) = self.post.channels.get(&channel_id) else {
                    return Ok(None);
                };
                if !projects(channel) {
                    return Ok(None);
                }
                let target_revision = channel.revision();
                let sequence = self.resulting_revision().get();
                let edges = route
                    .recipients()
                    .iter()
                    .filter_map(|user| self.home_of(user))
                    .collect();
                Ok(Some(ResolvedDelivery {
                    target: DeliveryTarget::Channel(channel_id),
                    target_revision,
                    sequence,
                    edges,
                }))
            }
            ResolvedMessageTarget::User(user_id) => {
                let mut edges = BTreeSet::new();
                edges.extend(self.home_of(sender));
                edges.extend(self.home_of(user_id));
                Ok(Some(ResolvedDelivery {
                    target: DeliveryTarget::User(user_id),
                    target_revision: Revision::new(0).map_err(|_| DomainError::LimitExceeded)?,
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
        let channel = self.post.channels.get(&channel_id)?;
        let invite = channel.invites.get(&invite_id)?;
        let inviter = self.source_view(invite.inviter)?;
        let named_target_user = match invite.target {
            Principal::Guest(user_id) => Some(user_id),
            Principal::Account(account_id) => self.context.named_target.or_else(|| {
                self.post
                    .sessions
                    .values()
                    .find(|session| session.account_id == Some(account_id))
                    .map(SessionState::user_id)
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
            resulting_revision: invite.creation_revision,
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
        let Some(target) = self
            .post
            .channels
            .get(&channel_id)
            .and_then(|channel| channel.invites.get(&invite_id))
            .map(|invite| invite.target)
        else {
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
        let account = self.post.accounts.get(&account_id)?;
        Some(AccountRecord {
            account_id,
            account_session_generation: account.session_generation(),
            account_revision: account.revision(),
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
            .post
            .sessions
            .values()
            .filter(|session| session.account_id == Some(account_id))
            .map(SessionState::user_id)
            .collect();
        let hosting: BTreeSet<ServerId> = sessions
            .iter()
            .filter_map(|user| self.home_of(*user))
            .collect();
        for edge in &hosting {
            self.emit(index, *edge, ProjectedEvent::AccountStateChanged(record));
        }
        let label_changed = self
            .pre
            .accounts
            .get(&account_id)
            .map(|account| account.label.clone())
            != self
                .post
                .accounts
                .get(&account_id)
                .map(|account| account.label().cloned());
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

    /// Every edge whose standing may change: homes of touched users before or
    /// after, holders of touched channels and accounts.
    fn touched_edges(&self) -> BTreeSet<ServerId> {
        let mut edges = BTreeSet::new();
        for user in &self.touched_users {
            edges.extend(self.home_of(*user));
            edges.extend(
                self.pre
                    .sessions
                    .get(user)
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
            if let Some(channel) = self.post.channels.get(channel_id) {
                for invite in channel.invites.values() {
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
            .receipt
            .events()
            .iter()
            .filter_map(|event| match event {
                DomainEvent::ChannelDestroyed(channel) => Some(*channel),
                _ => None,
            })
            .collect();
        for channel_id in channels {
            let destroyed = self.pre.channels.contains_key(&channel_id)
                && !self.post.channels.contains_key(&channel_id);
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
    /// post-state restricted to touched entities.
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
            let was_home = standing.is_some_and(|standing| standing.sessions.contains(user_id));
            match self.post_session(*user_id) {
                Some(session) if session.home_server_id() == edge => {
                    delta
                        .upserts
                        .push(ProjectionRecord::Session(session_record_of(
                            session, self.post,
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
            .post
            .channels
            .get(&channel_id)
            .map(|channel| channel.memberships.keys().copied().collect())
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
        let Some(channel) = self.post.channels.get(&channel_id) else {
            return BTreeMap::new();
        };
        channel
            .invites
            .values()
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

fn scalar_mode_changes(
    pre: &DurableChannel,
    post: &ChannelState,
    changes: &mut Vec<ProjectedModeChange>,
) {
    let key_before = pre.key_verifier.is_some();
    let key_after = post.key_verifier.is_some();
    if key_before != key_after {
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

fn projects(channel: &ChannelState) -> bool {
    channel.scope == ChannelScope::Global || channel.persistence == PersistencePolicy::Registered
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

fn source_view_of(session: &SessionState, state: &DomainState) -> SourceView {
    SourceView {
        user_id: session.user_id(),
        nickname: session.nickname().clone(),
        public_cloak: session.public_cloak(),
        account_label: session
            .account_id()
            .and_then(|account| state.accounts.get(&account))
            .and_then(|account| account.label().cloned()),
    }
}

/// Builds the standing session projection of one live session.
#[must_use]
pub fn session_record_of(session: &SessionState, state: &DomainState) -> SessionRecord {
    let source = source_view_of(session, state);
    SessionRecord {
        session_id: session.session_id(),
        user_id: session.user_id(),
        home_server_id: session.home_server_id(),
        session_revision: session.revision(),
        account: session
            .account_id()
            .map(|account| (account, session.account_session_generation())),
        nickname: source.nickname,
        display_name: session.display_name().clone(),
        public_cloak: source.public_cloak,
        account_label: source.account_label,
        user_mode_bits: user_mode_bits(session.operator_notices()),
        away: session.away().map(|text| text.as_str().to_owned()),
    }
}

/// Builds the standing channel detail of one channel.
#[must_use]
pub fn channel_detail_of(channel: &ChannelState) -> ChannelDetailRecord {
    ChannelDetailRecord {
        channel_id: channel.channel_id(),
        name: channel.name().clone(),
        channel_revision: channel.revision(),
        visibility: channel.visibility(),
        content_policy: channel.content_policy(),
        persistence: channel.persistence_policy(),
        simple_mode_bits: simple_mode_bits(channel.modes(), channel.visibility()),
        history: channel.history_policy(),
        e2ee_route_binding: None,
    }
}

#[cfg(test)]
#[path = "tests/projection.rs"]
mod tests;
