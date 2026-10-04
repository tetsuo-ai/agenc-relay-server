//! The edge's read-only committed replica of projected global state
//! (spec 20.8, 20.9, B.4, B.5, B.7).
//!
//! The replica accepts snapshot installs and ordered event applications and
//! enforces every Appendix-B consistency rule before the runtime renders a
//! client frame: revisions never regress, a state-changing event carries the
//! coordinator state generation it was produced at, memberships persist only
//! for local sessions, and an unreferenced account projection disappears with
//! its last local session.

use std::error::Error;
use std::fmt;

use std::collections::{BTreeMap, BTreeSet};

use agenc_relay_types::{AccountId, ChannelInstanceId, InviteId, Revision, ServerId, UserId};

use crate::Principal;
use crate::federation::record::{
    AccountRecord, ChannelDetailRecord, InviteRecord, InviteRemovalKind, MembershipRecord,
    ProjectedEvent, ProjectedModeChange, ProjectionKey, ProjectionRecord, SessionRecord,
};

/// Closed reasons an event or snapshot is refused as a fatal peer violation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplicaError {
    /// The event names a session, channel, invite, or account this edge does
    /// not hold, or holds a duplicate.
    UnknownEntity,
    /// A home projection or membership was addressed to another edge.
    WrongHome,
    /// A revision regressed, jumped past the generation, or repeated
    /// inconsistently.
    Revision,
    /// A home-session revision was present or absent contrary to locality.
    HomeSessionRevision,
    /// A membership, invite, or child record referenced an absent parent.
    DanglingReference,
    /// A snapshot entry set was not unique and sorted.
    SnapshotOrder,
    /// A channel was hidden while it still had local children.
    ChildrenRemain,
    /// A record's fields violate a B.4 invariant.
    InvalidRecord,
}

impl fmt::Display for ReplicaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnknownEntity => "federation replica entity is unknown or duplicated",
            Self::WrongHome => "federation replica record belongs to another home edge",
            Self::Revision => "federation replica revision is inconsistent",
            Self::HomeSessionRevision => "federation replica home-session revision is inconsistent",
            Self::DanglingReference => "federation replica reference does not resolve",
            Self::SnapshotOrder => "federation snapshot entries are not unique and sorted",
            Self::ChildrenRemain => "federation channel hidden while local children remain",
            Self::InvalidRecord => "federation projection record violates an invariant",
        };
        formatter.write_str(message)
    }
}

impl Error for ReplicaError {}

/// What the runtime must render or clean up after one applied event.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ApplyOutcome {
    /// Local users that should receive client output for this event.
    pub local_recipients: BTreeSet<UserId>,
    /// Standing entries deleted by this event, for durable erase before ACK.
    pub removed: Vec<ProjectionKey>,
    /// Standing entries inserted or replaced by this event.
    pub upserted: Vec<ProjectionKey>,
}

/// The installed projection of one edge.
#[derive(Clone, Eq, PartialEq)]
pub struct EdgeReplica {
    local_server_id: ServerId,
    projection_generation: u64,
    sessions: BTreeMap<UserId, SessionRecord>,
    channels: BTreeMap<ChannelInstanceId, ChannelDetailRecord>,
    memberships: BTreeMap<(ChannelInstanceId, UserId), MembershipRecord>,
    invites: BTreeMap<(ChannelInstanceId, InviteId), InviteRecord>,
    accounts: BTreeMap<AccountId, AccountRecord>,
}

/// Whether a validated entry set must also be closed under channel
/// entitlement: a coordinator snapshot is, an edge rebuilt from its own
/// durable rows is not (see `install_recovered`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Entitlement {
    /// Every channel must have a local member or an invite.
    Closed,
    /// A channel may stand between the two events that bracket it.
    Transient,
}

impl EdgeReplica {
    /// Creates an empty replica for the given local edge identity.
    #[must_use]
    pub fn new(local_server_id: ServerId) -> Self {
        Self {
            local_server_id,
            projection_generation: 0,
            sessions: BTreeMap::new(),
            channels: BTreeMap::new(),
            memberships: BTreeMap::new(),
            invites: BTreeMap::new(),
            accounts: BTreeMap::new(),
        }
    }

    /// Returns the installed projection generation.
    #[must_use]
    pub const fn projection_generation(&self) -> u64 {
        self.projection_generation
    }

    /// Returns the number of standing entries.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.sessions
            .len()
            .saturating_add(self.channels.len())
            .saturating_add(self.memberships.len())
            .saturating_add(self.invites.len())
            .saturating_add(self.accounts.len())
    }

    /// Returns one local session projection.
    #[must_use]
    pub fn session(&self, user_id: UserId) -> Option<&SessionRecord> {
        self.sessions.get(&user_id)
    }

    /// Returns one channel detail.
    #[must_use]
    pub fn channel(&self, channel_id: ChannelInstanceId) -> Option<&ChannelDetailRecord> {
        self.channels.get(&channel_id)
    }

    /// Returns one local membership.
    #[must_use]
    pub fn membership(
        &self,
        channel_id: ChannelInstanceId,
        user_id: UserId,
    ) -> Option<&MembershipRecord> {
        self.memberships.get(&(channel_id, user_id))
    }

    /// Returns one invite copy.
    #[must_use]
    pub fn invite(
        &self,
        channel_id: ChannelInstanceId,
        invite_id: InviteId,
    ) -> Option<&InviteRecord> {
        self.invites.get(&(channel_id, invite_id))
    }

    /// Returns one account projection.
    #[must_use]
    pub fn account(&self, account_id: AccountId) -> Option<&AccountRecord> {
        self.accounts.get(&account_id)
    }

    /// Iterates local members of a channel in User ID order.
    pub fn local_members(
        &self,
        channel_id: ChannelInstanceId,
    ) -> impl Iterator<Item = UserId> + '_ {
        self.memberships
            .range(
                (channel_id, UserId::from_bytes([0; 16]))
                    ..=(channel_id, UserId::from_bytes([u8::MAX; 16])),
            )
            .map(|((_, user), _)| *user)
    }

    /// Resolves a channel by its canonical name among the entitled details.
    #[must_use]
    pub fn channel_by_name(&self, name: &crate::ChannelNameValue) -> Option<&ChannelDetailRecord> {
        self.channels
            .values()
            .find(|channel| channel.name.canonical() == name.canonical())
    }

    /// Returns the current record under one standing key.
    #[must_use]
    pub fn record(&self, key: &ProjectionKey) -> Option<ProjectionRecord> {
        self.entries().find(|entry| entry.key() == *key)
    }

    /// Iterates the channels this edge is entitled to.
    pub fn channels(&self) -> impl Iterator<Item = &ChannelDetailRecord> + '_ {
        self.channels.values()
    }

    /// Iterates the local sessions.
    pub fn sessions(&self) -> impl Iterator<Item = &SessionRecord> + '_ {
        self.sessions.values()
    }

    /// Iterates every channel a local user belongs to.
    pub fn channels_of(&self, user_id: UserId) -> impl Iterator<Item = ChannelInstanceId> + '_ {
        self.memberships
            .keys()
            .filter(move |(_, member)| *member == user_id)
            .map(|(channel_id, _)| *channel_id)
    }

    /// Iterates every standing entry in snapshot order.
    pub fn entries(&self) -> impl Iterator<Item = ProjectionRecord> + '_ {
        let sessions = self
            .sessions
            .values()
            .cloned()
            .map(ProjectionRecord::Session);
        let channels = self
            .channels
            .values()
            .cloned()
            .map(ProjectionRecord::ChannelDetail);
        let memberships = self
            .memberships
            .values()
            .copied()
            .map(ProjectionRecord::Membership);
        let invites = self.invites.values().copied().map(ProjectionRecord::Invite);
        let accounts = self
            .accounts
            .values()
            .copied()
            .map(ProjectionRecord::Account);
        sessions
            .chain(channels)
            .chain(memberships)
            .chain(invites)
            .chain(accounts)
    }

    /// Installs a complete verified snapshot as the new generation.
    ///
    /// Entries must be unique and sorted by key; every reference must
    /// resolve within the set; no membership or session may belong to another
    /// home; no account may be unreferenced; and every channel must be one
    /// this edge is entitled to, which is what a coordinator snapshot always
    /// is.
    pub fn install(
        &mut self,
        projection_generation: u64,
        entries: Vec<ProjectionRecord>,
    ) -> Result<(), ReplicaError> {
        self.install_checked(projection_generation, entries, Entitlement::Closed)
    }

    /// Installs the generation this edge already holds, rebuilt from its own
    /// durable rows.
    ///
    /// This is the restore's install and it differs from a snapshot's in
    /// exactly one invariant: a channel with no local member and no invite is
    /// admitted. `apply` reaches that state and does not leave it — a channel
    /// becomes visible before the join that entitles the edge to it
    /// (`ChannelVisible` then `MemberJoined`), and it stays after the last
    /// local member goes (`SessionHidden` removes the memberships, and only
    /// the coordinator's later `ChannelHidden` removes the channel). Each of
    /// those events is its own durable batch, so between two of them a
    /// correctly running edge is durably holding a channel the closure check
    /// refuses. Refusing it here would brick an edge that crossed no rule, and
    /// only a restart would reveal it (RUN-08, issue #134). Every other
    /// invariant still refuses: a membership, invite or child whose parent is
    /// absent, a foreign home, a revision fault, an unsorted or duplicated
    /// set, an unreferenced account, and every per-record rule.
    pub fn install_recovered(
        &mut self,
        projection_generation: u64,
        entries: Vec<ProjectionRecord>,
    ) -> Result<(), ReplicaError> {
        self.install_checked(projection_generation, entries, Entitlement::Transient)
    }

    fn install_checked(
        &mut self,
        projection_generation: u64,
        entries: Vec<ProjectionRecord>,
        entitlement: Entitlement,
    ) -> Result<(), ReplicaError> {
        let mut candidate = Self::new(self.local_server_id);
        candidate.projection_generation = projection_generation;
        let mut previous: Option<ProjectionKey> = None;
        for entry in entries {
            let key = entry.key();
            if previous.as_ref().is_some_and(|prior| prior >= &key) {
                return Err(ReplicaError::SnapshotOrder);
            }
            previous = Some(key);
            candidate.insert_unchecked(entry)?;
        }
        candidate.validate_with(entitlement)?;
        *self = candidate;
        Ok(())
    }

    /// Checks every B.4 and B.7 structural invariant.
    pub fn validate(&self) -> Result<(), ReplicaError> {
        self.validate_with(Entitlement::Closed)
    }

    fn validate_with(&self, entitlement: Entitlement) -> Result<(), ReplicaError> {
        self.validate_sessions()?;
        self.validate_children()?;
        if entitlement == Entitlement::Closed {
            for channel_id in self.channels.keys() {
                if !self.has_entitlement(*channel_id) {
                    return Err(ReplicaError::DanglingReference);
                }
            }
        }
        for account_id in self.accounts.keys() {
            if !self.hosts_principal(Principal::Account(*account_id)) {
                return Err(ReplicaError::DanglingReference);
            }
        }
        Ok(())
    }

    fn validate_sessions(&self) -> Result<(), ReplicaError> {
        for session in self.sessions.values() {
            if session.home_server_id != self.local_server_id {
                return Err(ReplicaError::WrongHome);
            }
            validate_session(session)?;
            if let Some((account_id, generation)) = session.account {
                let account = self
                    .accounts
                    .get(&account_id)
                    .ok_or(ReplicaError::DanglingReference)?;
                if account.account_session_generation != generation {
                    return Err(ReplicaError::InvalidRecord);
                }
            }
        }
        Ok(())
    }

    /// Every membership and invite is keyed by its own record identifiers at
    /// insertion, so only the references they carry can dangle.
    fn validate_children(&self) -> Result<(), ReplicaError> {
        for (channel_id, user_id) in self.memberships.keys() {
            if !self.channels.contains_key(channel_id) || !self.sessions.contains_key(user_id) {
                return Err(ReplicaError::DanglingReference);
            }
        }
        self.validate_invites()
    }

    fn validate_invites(&self) -> Result<(), ReplicaError> {
        for (channel_id, invite) in self
            .invites
            .iter()
            .map(|((channel, _), invite)| (channel, invite))
        {
            if !self.channels.contains_key(channel_id) || !self.hosts_principal(invite.target) {
                return Err(ReplicaError::DanglingReference);
            }
        }
        Ok(())
    }

    /// Applies one ordered event from the active generation.
    ///
    /// `coordinator_state_generation` is the event's generation; a
    /// state-changing event must carry it as the resulting revision.
    // agenc-review: focus owner=domain reviewed=2026-09-02 reason=one closed dispatcher applies every projected event kind under its B.5 rule
    pub fn apply(
        &mut self,
        event: &ProjectedEvent,
        coordinator_state_generation: u64,
    ) -> Result<ApplyOutcome, ReplicaError> {
        let generation =
            Revision::new(coordinator_state_generation).map_err(|_| ReplicaError::Revision)?;
        let mut outcome = ApplyOutcome::default();
        match event {
            ProjectedEvent::SessionVisible(view) => {
                self.apply_session_view(
                    view.home_projection.as_ref(),
                    view.source.user_id,
                    &mut outcome,
                )?;
                outcome.local_recipients.extend(self.monitor_recipients());
            }
            ProjectedEvent::SessionHidden {
                source, channels, ..
            } => self.apply_session_hidden(source.user_id, channels, generation, &mut outcome)?,
            ProjectedEvent::NicknameChanged { view, .. }
            | ProjectedEvent::AwayChanged { view, .. }
            | ProjectedEvent::DisplayNameChanged { view, .. }
            | ProjectedEvent::AccountLabelChanged(view) => {
                self.apply_session_view(
                    view.home_projection.as_ref(),
                    view.source.user_id,
                    &mut outcome,
                )?;
                outcome
                    .local_recipients
                    .extend(self.shared_recipients(view.source.user_id));
            }
            ProjectedEvent::ChannelVisible(detail) => {
                if self.channels.contains_key(&detail.channel_id) {
                    return Err(ReplicaError::UnknownEntity);
                }
                validate_detail(detail)?;
                outcome
                    .upserted
                    .push(ProjectionKey::channel_detail(detail.channel_id));
                self.channels.insert(detail.channel_id, detail.clone());
            }
            ProjectedEvent::ChannelHidden {
                channel_id,
                last_revision,
            } => {
                self.expect_channel_revision(
                    *channel_id,
                    *last_revision,
                    generation,
                    false,
                    &mut outcome,
                )?;
                if self.local_members(*channel_id).next().is_some()
                    || self
                        .invites
                        .keys()
                        .any(|(channel, _)| channel == channel_id)
                {
                    return Err(ReplicaError::ChildrenRemain);
                }
                self.channels.remove(channel_id);
                outcome
                    .removed
                    .push(ProjectionKey::channel_detail(*channel_id));
            }
            ProjectedEvent::MemberJoined {
                view,
                home_session_revision,
                ..
            } => {
                let channel_id = view.membership.channel_id;
                let user_id = view.membership.user_id;
                self.expect_channel_revision(
                    channel_id,
                    view.membership.membership_revision,
                    generation,
                    true,
                    &mut outcome,
                )?;
                self.advance_home_session(
                    user_id,
                    *home_session_revision,
                    generation,
                    &mut outcome,
                )?;
                if self.sessions.contains_key(&user_id) {
                    if self.memberships.contains_key(&(channel_id, user_id)) {
                        return Err(ReplicaError::UnknownEntity);
                    }
                    self.memberships
                        .insert((channel_id, user_id), view.membership);
                    outcome
                        .upserted
                        .push(ProjectionKey::membership(channel_id, user_id));
                }
                outcome
                    .local_recipients
                    .extend(self.local_members(channel_id));
            }
            ProjectedEvent::MemberParted {
                channel_id,
                source,
                resulting_revision,
                home_session_revision,
                ..
            } => {
                outcome
                    .local_recipients
                    .extend(self.local_members(*channel_id));
                self.expect_channel_revision(
                    *channel_id,
                    *resulting_revision,
                    generation,
                    true,
                    &mut outcome,
                )?;
                self.advance_home_session(
                    source.user_id,
                    *home_session_revision,
                    generation,
                    &mut outcome,
                )?;
                self.remove_membership(*channel_id, source.user_id, &mut outcome);
            }
            ProjectedEvent::Kicked {
                channel_id,
                target,
                resulting_revision,
                target_home_session_revision,
                ..
            } => {
                outcome
                    .local_recipients
                    .extend(self.local_members(*channel_id));
                self.expect_channel_revision(
                    *channel_id,
                    *resulting_revision,
                    generation,
                    true,
                    &mut outcome,
                )?;
                self.advance_home_session(
                    target.user_id,
                    *target_home_session_revision,
                    generation,
                    &mut outcome,
                )?;
                self.remove_membership(*channel_id, target.user_id, &mut outcome);
            }
            ProjectedEvent::ChannelModesChanged {
                channel_id,
                resulting_revision,
                changes,
                ..
            } => {
                self.expect_channel_revision(
                    *channel_id,
                    *resulting_revision,
                    generation,
                    true,
                    &mut outcome,
                )?;
                self.apply_mode_changes(*channel_id, changes, &mut outcome)?;
                outcome
                    .local_recipients
                    .extend(self.local_members(*channel_id));
            }
            ProjectedEvent::TopicChanged {
                channel_id,
                resulting_revision,
                ..
            }
            | ProjectedEvent::ChannelMembershipsRecomputed {
                channel_id,
                resulting_revision,
                ..
            } => {
                self.expect_channel_revision(
                    *channel_id,
                    *resulting_revision,
                    generation,
                    true,
                    &mut outcome,
                )?;
                if let ProjectedEvent::ChannelMembershipsRecomputed { memberships, .. } = event {
                    for view in memberships {
                        if view.membership.channel_id != *channel_id {
                            return Err(ReplicaError::InvalidRecord);
                        }
                        if let Some(existing) = self
                            .memberships
                            .get_mut(&(*channel_id, view.membership.user_id))
                        {
                            // A recompute changes roles only (architecture
                            // 13.2): a member keeps the revision it joined
                            // at, which its history authorization compares,
                            // and the second it joined.
                            let recomputed = MembershipRecord {
                                role: view.membership.role,
                                ..*existing
                            };
                            if view.membership != recomputed {
                                return Err(ReplicaError::InvalidRecord);
                            }
                            *existing = view.membership;
                            outcome.upserted.push(ProjectionKey::membership(
                                *channel_id,
                                view.membership.user_id,
                            ));
                        }
                    }
                }
                outcome
                    .local_recipients
                    .extend(self.local_members(*channel_id));
            }
            ProjectedEvent::Invited {
                channel_id,
                invite_id,
                resulting_revision,
                local_projection,
                inviter,
                ..
            } => {
                // A local inviter sees the confirmation numeric whether or
                // not this edge hosts the target.
                if self.sessions.contains_key(&inviter.user_id) {
                    outcome.local_recipients.insert(inviter.user_id);
                }
                if let Some(record) = local_projection {
                    if record.channel_id != *channel_id || record.invite_id != *invite_id {
                        return Err(ReplicaError::InvalidRecord);
                    }
                    if !self.channels.contains_key(channel_id)
                        || !self.hosts_principal(record.target)
                    {
                        return Err(ReplicaError::DanglingReference);
                    }
                    if self.invites.contains_key(&(*channel_id, *invite_id)) {
                        return Err(ReplicaError::UnknownEntity);
                    }
                    self.bump_channel_revision(
                        *channel_id,
                        *resulting_revision,
                        generation,
                        &mut outcome,
                    )?;
                    self.invites.insert((*channel_id, *invite_id), *record);
                    outcome
                        .upserted
                        .push(ProjectionKey::invite(*channel_id, *invite_id));
                    outcome
                        .local_recipients
                        .extend(self.principal_users(record.target));
                } else {
                    // The invite advanced the channel on the coordinator, so a
                    // member edge that hosts no target still takes the revision.
                    self.bump_channel_revision(
                        *channel_id,
                        *resulting_revision,
                        generation,
                        &mut outcome,
                    )?;
                    outcome
                        .local_recipients
                        .extend(self.local_members(*channel_id));
                }
            }
            ProjectedEvent::InviteRemoved {
                channel_id,
                invite_id,
                resulting_revision,
                kind,
            } => {
                let record = self
                    .invites
                    .remove(&(*channel_id, *invite_id))
                    .ok_or(ReplicaError::UnknownEntity)?;
                if *kind == InviteRemovalKind::ProjectionHidden {
                    self.expect_channel_revision(
                        *channel_id,
                        *resulting_revision,
                        generation,
                        false,
                        &mut outcome,
                    )?;
                } else {
                    self.expect_channel_revision(
                        *channel_id,
                        *resulting_revision,
                        generation,
                        true,
                        &mut outcome,
                    )?;
                }
                outcome
                    .removed
                    .push(ProjectionKey::invite(*channel_id, *invite_id));
                outcome
                    .local_recipients
                    .extend(self.principal_users(record.target));
            }
            ProjectedEvent::MessageDelivered(message) => match message.target {
                crate::federation::record::DeliveryTarget::Channel(channel_id) => {
                    let detail = self
                        .channels
                        .get(&channel_id)
                        .ok_or(ReplicaError::UnknownEntity)?;
                    if detail.channel_revision != message.target_revision {
                        return Err(ReplicaError::Revision);
                    }
                    outcome
                        .local_recipients
                        .extend(self.local_members(channel_id));
                }
                crate::federation::record::DeliveryTarget::User(user_id) => {
                    if self.sessions.contains_key(&user_id) {
                        outcome.local_recipients.insert(user_id);
                    }
                    if self.sessions.contains_key(&message.sender.user_id) {
                        outcome.local_recipients.insert(message.sender.user_id);
                    }
                }
            },
            ProjectedEvent::ChannelDestroyed {
                channel_id,
                final_revision,
            } => {
                self.expect_channel_revision(
                    *channel_id,
                    *final_revision,
                    generation,
                    true,
                    &mut outcome,
                )?;
                outcome
                    .local_recipients
                    .extend(self.local_members(*channel_id));
                let members: Vec<UserId> = self.local_members(*channel_id).collect();
                for user_id in members {
                    self.remove_membership(*channel_id, user_id, &mut outcome);
                }
                let invites: Vec<InviteId> = self
                    .invites
                    .keys()
                    .filter(|(channel, _)| channel == channel_id)
                    .map(|(_, invite)| *invite)
                    .collect();
                for invite_id in invites {
                    self.invites.remove(&(*channel_id, invite_id));
                    outcome
                        .removed
                        .push(ProjectionKey::invite(*channel_id, invite_id));
                }
                self.channels.remove(channel_id);
                outcome
                    .removed
                    .push(ProjectionKey::channel_detail(*channel_id));
            }
            ProjectedEvent::NetworkNotice { .. } => {
                outcome
                    .local_recipients
                    .extend(self.sessions.keys().copied());
            }
            ProjectedEvent::UserModesChanged(record) => {
                self.apply_session_view(Some(record), record.user_id, &mut outcome)?;
            }
            ProjectedEvent::ChannelPolicyChanged(detail) => {
                let existing = self
                    .channels
                    .get_mut(&detail.channel_id)
                    .ok_or(ReplicaError::UnknownEntity)?;
                if detail.channel_revision.get() < existing.channel_revision.get()
                    || detail.channel_revision != generation
                {
                    return Err(ReplicaError::Revision);
                }
                validate_detail(detail)?;
                *existing = detail.clone();
                outcome
                    .upserted
                    .push(ProjectionKey::channel_detail(detail.channel_id));
                outcome
                    .local_recipients
                    .extend(self.local_members(detail.channel_id));
            }
            ProjectedEvent::AccountStateChanged(record) => {
                if !self.hosts_principal(Principal::Account(record.account_id)) {
                    return Err(ReplicaError::DanglingReference);
                }
                if let Some(existing) = self.accounts.get(&record.account_id)
                    && existing.account_revision.get() > record.account_revision.get()
                {
                    return Err(ReplicaError::Revision);
                }
                self.accounts.insert(record.account_id, *record);
                outcome
                    .upserted
                    .push(ProjectionKey::account(record.account_id));
                outcome
                    .local_recipients
                    .extend(self.principal_users(Principal::Account(record.account_id)));
            }
            ProjectedEvent::RequestCompleted { .. } => {}
        }
        // A row removed by this event supersedes its earlier revision bump.
        // Several effects may update the same surviving row; persist it once.
        outcome
            .upserted
            .retain(|key| !outcome.removed.contains(key));
        outcome.upserted.sort_unstable();
        outcome.upserted.dedup();
        Ok(outcome)
    }

    fn insert_unchecked(&mut self, entry: ProjectionRecord) -> Result<(), ReplicaError> {
        match entry {
            ProjectionRecord::Session(record) => {
                validate_session(&record)?;
                self.sessions.insert(record.user_id, record);
            }
            ProjectionRecord::ChannelDetail(record) => {
                validate_detail(&record)?;
                self.channels.insert(record.channel_id, record);
            }
            ProjectionRecord::Membership(record) => {
                self.memberships
                    .insert((record.channel_id, record.user_id), record);
            }
            ProjectionRecord::Invite(record) => {
                self.invites
                    .insert((record.channel_id, record.invite_id), record);
            }
            ProjectionRecord::Account(record) => {
                if record.account_session_generation.get() == 0
                    || record.account_revision.get() == 0
                {
                    return Err(ReplicaError::InvalidRecord);
                }
                self.accounts.insert(record.account_id, record);
            }
        }
        Ok(())
    }

    fn hosts_principal(&self, principal: Principal) -> bool {
        match principal {
            Principal::Guest(user_id) => self.sessions.contains_key(&user_id),
            Principal::Account(account_id) => self
                .sessions
                .values()
                .any(|session| session.account.is_some_and(|(id, _)| id == account_id)),
        }
    }

    fn principal_users(&self, principal: Principal) -> Vec<UserId> {
        match principal {
            Principal::Guest(user_id) => self
                .sessions
                .contains_key(&user_id)
                .then_some(user_id)
                .into_iter()
                .collect(),
            Principal::Account(account_id) => self
                .sessions
                .values()
                .filter(|session| session.account.is_some_and(|(id, _)| id == account_id))
                .map(|session| session.user_id)
                .collect(),
        }
    }

    fn has_entitlement(&self, channel_id: ChannelInstanceId) -> bool {
        self.local_members(channel_id).next().is_some()
            || self
                .invites
                .keys()
                .any(|(channel, _)| *channel == channel_id)
    }

    fn monitor_recipients(&self) -> Vec<UserId> {
        Vec::new()
    }

    fn shared_recipients(&self, user_id: UserId) -> BTreeSet<UserId> {
        let mut recipients = BTreeSet::new();
        let channels: Vec<ChannelInstanceId> = self
            .memberships
            .keys()
            .filter(|(_, member)| *member == user_id)
            .map(|(channel, _)| *channel)
            .collect();
        for channel_id in channels {
            recipients.extend(self.local_members(channel_id));
        }
        if self.sessions.contains_key(&user_id) {
            recipients.insert(user_id);
        }
        recipients
    }

    fn apply_session_view(
        &mut self,
        home_projection: Option<&SessionRecord>,
        user_id: UserId,
        outcome: &mut ApplyOutcome,
    ) -> Result<(), ReplicaError> {
        let Some(record) = home_projection else {
            if self.sessions.contains_key(&user_id) {
                return Err(ReplicaError::HomeSessionRevision);
            }
            return Ok(());
        };
        self.check_home_record(record, user_id)?;
        let previous_account = self
            .sessions
            .get(&user_id)
            .and_then(|session| session.account);
        self.sessions.insert(user_id, record.clone());
        outcome.upserted.push(ProjectionKey::session(user_id));
        outcome.local_recipients.insert(user_id);
        if let Some((previous, _)) = previous_account
            && record
                .account
                .is_none_or(|(current, _)| current != previous)
        {
            self.drop_unreferenced_account(previous, outcome);
        }
        Ok(())
    }

    /// Checks identity, home, invariants, revision monotonicity, and account
    /// generation agreement of one incoming home projection.
    fn check_home_record(
        &self,
        record: &SessionRecord,
        user_id: UserId,
    ) -> Result<(), ReplicaError> {
        if record.user_id != user_id {
            return Err(ReplicaError::InvalidRecord);
        }
        if record.home_server_id != self.local_server_id {
            return Err(ReplicaError::WrongHome);
        }
        validate_session(record)?;
        if let Some(existing) = self.sessions.get(&user_id)
            && existing.session_revision.get() > record.session_revision.get()
        {
            return Err(ReplicaError::Revision);
        }
        if let Some((account_id, generation)) = record.account
            && let Some(account) = self.accounts.get(&account_id)
            && account.account_session_generation != generation
        {
            return Err(ReplicaError::InvalidRecord);
        }
        Ok(())
    }

    fn apply_session_hidden(
        &mut self,
        user_id: UserId,
        channels: &[(ChannelInstanceId, Revision)],
        generation: Revision,
        outcome: &mut ApplyOutcome,
    ) -> Result<(), ReplicaError> {
        let mut previous: Option<ChannelInstanceId> = None;
        for (channel_id, revision) in channels {
            if previous.is_some_and(|prior| prior >= *channel_id) {
                return Err(ReplicaError::SnapshotOrder);
            }
            previous = Some(*channel_id);
            self.expect_channel_revision(*channel_id, *revision, generation, true, outcome)?;
            outcome
                .local_recipients
                .extend(self.local_members(*channel_id));
        }
        let Some(session) = self.sessions.remove(&user_id) else {
            return Ok(());
        };
        outcome.removed.push(ProjectionKey::session(user_id));
        let joined: Vec<ChannelInstanceId> = self
            .memberships
            .keys()
            .filter(|(_, member)| *member == user_id)
            .map(|(channel, _)| *channel)
            .collect();
        for channel_id in joined {
            if !channels.iter().any(|(listed, _)| *listed == channel_id) {
                return Err(ReplicaError::DanglingReference);
            }
            self.memberships.remove(&(channel_id, user_id));
            outcome
                .removed
                .push(ProjectionKey::membership(channel_id, user_id));
        }
        if let Some((account_id, _)) = session.account {
            self.drop_unreferenced_account(account_id, outcome);
        }
        Ok(())
    }

    fn drop_unreferenced_account(&mut self, account_id: AccountId, outcome: &mut ApplyOutcome) {
        if self.hosts_principal(Principal::Account(account_id)) {
            return;
        }
        if self.accounts.remove(&account_id).is_some() {
            outcome.removed.push(ProjectionKey::account(account_id));
        }
    }

    fn remove_membership(
        &mut self,
        channel_id: ChannelInstanceId,
        user_id: UserId,
        outcome: &mut ApplyOutcome,
    ) {
        if self.memberships.remove(&(channel_id, user_id)).is_some() {
            outcome
                .removed
                .push(ProjectionKey::membership(channel_id, user_id));
        }
    }

    /// Checks the carried revision against the installed detail: a
    /// state-changing event carries the generation and never regresses; a
    /// non-changing copy repeats the installed value.
    fn expect_channel_revision(
        &mut self,
        channel_id: ChannelInstanceId,
        carried: Revision,
        generation: Revision,
        state_changing: bool,
        outcome: &mut ApplyOutcome,
    ) -> Result<(), ReplicaError> {
        if state_changing {
            return self.bump_channel_revision(channel_id, carried, generation, outcome);
        }
        let detail = self
            .channels
            .get(&channel_id)
            .ok_or(ReplicaError::UnknownEntity)?;
        if carried != detail.channel_revision && carried != generation {
            return Err(ReplicaError::Revision);
        }
        Ok(())
    }

    fn bump_channel_revision(
        &mut self,
        channel_id: ChannelInstanceId,
        carried: Revision,
        generation: Revision,
        outcome: &mut ApplyOutcome,
    ) -> Result<(), ReplicaError> {
        let detail = self
            .channels
            .get_mut(&channel_id)
            .ok_or(ReplicaError::UnknownEntity)?;
        if carried.get() < detail.channel_revision.get() {
            return Err(ReplicaError::Revision);
        }
        if carried != generation && carried != detail.channel_revision {
            return Err(ReplicaError::Revision);
        }
        if detail.channel_revision != carried {
            detail.channel_revision = carried;
            outcome
                .upserted
                .push(ProjectionKey::channel_detail(channel_id));
        }
        Ok(())
    }

    fn advance_home_session(
        &mut self,
        user_id: UserId,
        home_session_revision: Option<Revision>,
        generation: Revision,
        outcome: &mut ApplyOutcome,
    ) -> Result<(), ReplicaError> {
        match (self.sessions.get_mut(&user_id), home_session_revision) {
            (Some(session), Some(revision)) => {
                if revision.get() < session.session_revision.get() || revision != generation {
                    return Err(ReplicaError::HomeSessionRevision);
                }
                if session.session_revision != revision {
                    session.session_revision = revision;
                    outcome.upserted.push(ProjectionKey::session(user_id));
                }
                Ok(())
            }
            (None, None) => Ok(()),
            _ => Err(ReplicaError::HomeSessionRevision),
        }
    }

    fn apply_mode_changes(
        &mut self,
        channel_id: ChannelInstanceId,
        changes: &[ProjectedModeChange],
        outcome: &mut ApplyOutcome,
    ) -> Result<(), ReplicaError> {
        if !self.channels.contains_key(&channel_id) {
            return Err(ReplicaError::UnknownEntity);
        }
        for change in changes {
            self.apply_mode_change(channel_id, change, outcome)?;
        }
        outcome
            .upserted
            .push(ProjectionKey::channel_detail(channel_id));
        Ok(())
    }

    fn apply_mode_change(
        &mut self,
        channel_id: ChannelInstanceId,
        change: &ProjectedModeChange,
        outcome: &mut ApplyOutcome,
    ) -> Result<(), ReplicaError> {
        match change {
            ProjectedModeChange::Simple {
                direction,
                mode_code,
            } => self.apply_simple_mode(channel_id, *direction, *mode_code),
            ProjectedModeChange::Prefix { view, .. } => {
                if view.membership.channel_id != channel_id {
                    return Err(ReplicaError::InvalidRecord);
                }
                let key = (channel_id, view.membership.user_id);
                if let Some(existing) = self.memberships.get_mut(&key) {
                    *existing = view.membership;
                    outcome.upserted.push(ProjectionKey::membership(
                        channel_id,
                        view.membership.user_id,
                    ));
                }
                Ok(())
            }
            ProjectedModeChange::List { entry, .. } => {
                if entry.channel_id != channel_id || !(1..=3).contains(&entry.mode_code) {
                    return Err(ReplicaError::InvalidRecord);
                }
                Ok(())
            }
            ProjectedModeChange::Key { .. } | ProjectedModeChange::Limit { .. } => Ok(()),
        }
    }

    fn apply_simple_mode(
        &mut self,
        channel_id: ChannelInstanceId,
        direction: crate::federation::record::ModeDirection,
        mode_code: u16,
    ) -> Result<(), ReplicaError> {
        let bit = simple_bit(mode_code).ok_or(ReplicaError::InvalidRecord)?;
        let detail = self
            .channels
            .get_mut(&channel_id)
            .ok_or(ReplicaError::UnknownEntity)?;
        match direction {
            crate::federation::record::ModeDirection::Add => detail.simple_mode_bits |= bit,
            crate::federation::record::ModeDirection::Remove => detail.simple_mode_bits &= !bit,
        }
        Ok(())
    }
}

fn simple_bit(mode_code: u16) -> Option<u16> {
    match mode_code {
        6 => Some(1),
        7 => Some(1 << 1),
        8 => Some(1 << 2),
        9 => Some(1 << 3),
        10 => Some(1 << 4),
        11 => Some(1 << 5),
        _ => None,
    }
}

fn validate_session(record: &SessionRecord) -> Result<(), ReplicaError> {
    if record.user_mode_bits & 1 == 0 || record.user_mode_bits > 3 {
        return Err(ReplicaError::InvalidRecord);
    }
    match record.account {
        Some((_, generation)) if generation.get() == 0 => Err(ReplicaError::InvalidRecord),
        None if record.account_label.is_some() => Err(ReplicaError::InvalidRecord),
        _ => Ok(()),
    }
}

fn validate_detail(record: &ChannelDetailRecord) -> Result<(), ReplicaError> {
    let bits = record.simple_mode_bits;
    if bits & (1 << 2) == 0 || bits > 0b11_1111 || (bits & (1 << 3) != 0 && bits & (1 << 4) != 0) {
        return Err(ReplicaError::InvalidRecord);
    }
    if record.channel_revision.get() == 0 {
        return Err(ReplicaError::InvalidRecord);
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/replica.rs"]
mod tests;
