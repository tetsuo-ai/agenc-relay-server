//! Recipient-authorized projections with no transport or credential fields.

use agenc_ircd_types::{AccountId, ChannelInstanceId, PublicCloak, UserId};

use crate::{
    AccountLabelValue, ChannelNameValue, ContentPolicy, DisplayNameValue, DomainError, DomainState,
    NicknameValue, PresencePolicy, Role, SessionState, Visibility,
};

const MAX_LIST_RESULTS: usize = 200;

/// A visibility decision that never distinguishes hidden from absent targets.
pub enum ProjectionDecision<Visible> {
    /// The requester may receive the bounded projection.
    Visible(Visible),
    /// The requester receives the same result for hidden and absent state.
    Hidden,
}

/// Public account fields visible to one of that account's own sessions.
pub struct AccountProjection<'a> {
    account_id: AccountId,
    label: Option<&'a AccountLabelValue>,
    presence: crate::PresencePolicy,
    guest_direct_messages: crate::GuestDirectMessagePolicy,
    direct_messages: crate::DirectMessagePolicy,
}

impl AccountProjection<'_> {
    /// Returns the immutable account authority.
    #[must_use]
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Borrows the optional public label.
    #[must_use]
    pub const fn label(&self) -> Option<&AccountLabelValue> {
        self.label
    }

    /// Returns the account-wide presence setting.
    #[must_use]
    pub const fn presence(&self) -> crate::PresencePolicy {
        self.presence
    }

    /// Returns the guest direct-message setting.
    #[must_use]
    pub const fn guest_direct_messages(&self) -> crate::GuestDirectMessagePolicy {
        self.guest_direct_messages
    }

    /// Returns the authenticated direct-message setting.
    #[must_use]
    pub const fn direct_messages(&self) -> crate::DirectMessagePolicy {
        self.direct_messages
    }
}

/// Client-visible session identity with transport and private account state omitted.
pub struct SessionProjection<'a> {
    user_id: UserId,
    nickname: &'a NicknameValue,
    display_name: &'a DisplayNameValue,
    public_cloak: PublicCloak,
    account_label: Option<&'a AccountLabelValue>,
    away_text: Option<&'a str>,
}

impl SessionProjection<'_> {
    /// Returns the ephemeral per-connection identity.
    #[must_use]
    pub const fn user_id(&self) -> UserId {
        self.user_id
    }

    /// Borrows the mutable routing nickname.
    #[must_use]
    pub const fn nickname(&self) -> &NicknameValue {
        self.nickname
    }

    /// Borrows the prepared display name.
    #[must_use]
    pub const fn display_name(&self) -> &DisplayNameValue {
        self.display_name
    }

    /// Returns the independently random visible cloak.
    #[must_use]
    pub const fn public_cloak(&self) -> PublicCloak {
        self.public_cloak
    }

    /// Borrows the public account label, never a login identifier.
    #[must_use]
    pub const fn account_label(&self) -> Option<&AccountLabelValue> {
        self.account_label
    }

    /// Borrows the policy-visible away text.
    #[must_use]
    pub const fn away_text(&self) -> Option<&str> {
        self.away_text
    }
}

/// Presence result with idle time and transport state deliberately absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresenceProjection {
    /// The authorized target has one or more visible live sessions.
    Present,
    /// Hidden and offline targets share this result.
    Absent,
}

/// One member row visible inside an authorized channel projection.
pub struct MemberProjection<'a> {
    user_id: UserId,
    nickname: &'a NicknameValue,
    display_name: &'a DisplayNameValue,
    role: Role,
}

impl MemberProjection<'_> {
    /// Returns the live user identity.
    #[must_use]
    pub const fn user_id(&self) -> UserId {
        self.user_id
    }

    /// Borrows the routing nickname.
    #[must_use]
    pub const fn nickname(&self) -> &NicknameValue {
        self.nickname
    }

    /// Borrows the prepared display name.
    #[must_use]
    pub const fn display_name(&self) -> &DisplayNameValue {
        self.display_name
    }

    /// Returns the highest effective role.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }
}

/// Topic value safe for one authorized channel view.
pub enum TopicProjection<'a> {
    /// Validated plaintext topic text.
    Plaintext(&'a str),
    /// Fixed public placeholder for an encrypted route.
    EncryptedPlaceholder,
    /// No topic is set.
    None,
}

/// Full channel view available only after exact visibility authorization.
pub struct ChannelProjection<'a> {
    channel_id: ChannelInstanceId,
    name: &'a ChannelNameValue,
    visibility: Visibility,
    topic: TopicProjection<'a>,
    members: Vec<MemberProjection<'a>>,
}

impl<'a> ChannelProjection<'a> {
    /// Returns the channel creation identity.
    #[must_use]
    pub const fn channel_id(&self) -> ChannelInstanceId {
        self.channel_id
    }

    /// Borrows the stable channel name.
    #[must_use]
    pub const fn name(&self) -> &'a ChannelNameValue {
        self.name
    }

    /// Returns the discovery policy.
    #[must_use]
    pub const fn visibility(&self) -> Visibility {
        self.visibility
    }

    /// Borrows the authorized topic representation.
    #[must_use]
    pub const fn topic(&self) -> &TopicProjection<'a> {
        &self.topic
    }

    /// Borrows members in deterministic User-ID order.
    #[must_use]
    pub fn members(&self) -> &[MemberProjection<'a>] {
        &self.members
    }
}

/// One privacy-bucketed LIST row.
pub struct ChannelListProjection<'a> {
    channel_id: ChannelInstanceId,
    name: &'a ChannelNameValue,
    member_count_lower_bound: u16,
    topic: TopicProjection<'a>,
}

impl<'a> ChannelListProjection<'a> {
    /// Returns the current channel creation identity.
    #[must_use]
    pub const fn channel_id(&self) -> ChannelInstanceId {
        self.channel_id
    }

    /// Borrows the stable channel name.
    #[must_use]
    pub const fn name(&self) -> &'a ChannelNameValue {
        self.name
    }

    /// Returns the lower bound of the documented privacy bucket.
    #[must_use]
    pub const fn member_count_lower_bound(&self) -> u16 {
        self.member_count_lower_bound
    }

    /// Borrows plaintext or the fixed encrypted placeholder.
    #[must_use]
    pub const fn topic(&self) -> &TopicProjection<'a> {
        &self.topic
    }
}

impl DomainState {
    /// Projects account settings only to a live session of that same account.
    #[must_use]
    pub fn project_account(
        &self,
        requester: UserId,
        account_id: AccountId,
    ) -> ProjectionDecision<AccountProjection<'_>> {
        let Some(session) = self.session(requester) else {
            return ProjectionDecision::Hidden;
        };
        if session.account_id != Some(account_id) {
            return ProjectionDecision::Hidden;
        }
        let Some(account) = self.accounts.get(&account_id) else {
            return ProjectionDecision::Hidden;
        };
        ProjectionDecision::Visible(AccountProjection {
            account_id,
            label: account.label.as_ref(),
            presence: account.presence,
            guest_direct_messages: account.guest_direct_messages,
            direct_messages: account.direct_messages,
        })
    }

    /// Projects one session only through self, shared-channel, or mutual-contact context.
    #[must_use]
    pub fn project_session(
        &self,
        requester: UserId,
        target: UserId,
    ) -> ProjectionDecision<SessionProjection<'_>> {
        let Some(target_session) = self.session(target) else {
            return ProjectionDecision::Hidden;
        };
        if !self.session_is_visible(requester, target_session) {
            return ProjectionDecision::Hidden;
        }
        ProjectionDecision::Visible(self.session_projection(requester, target_session))
    }

    /// Returns presence without distinguishing an offline target from a hidden one.
    #[must_use]
    pub fn project_presence(&self, requester: UserId, target: UserId) -> PresenceProjection {
        match self.session(target) {
            Some(session) if self.session_is_visible(requester, session) => {
                PresenceProjection::Present
            }
            _ => PresenceProjection::Absent,
        }
    }

    /// Builds one exact channel view after applying secret-channel rules.
    pub fn project_channel(
        &self,
        requester: UserId,
        channel_id: ChannelInstanceId,
    ) -> Result<ProjectionDecision<ChannelProjection<'_>>, DomainError> {
        let Some(channel) = self.channels.get(&channel_id) else {
            return Ok(ProjectionDecision::Hidden);
        };
        if channel.visibility != Visibility::Listed && !channel.memberships.contains_key(&requester)
        {
            return Ok(ProjectionDecision::Hidden);
        }
        let mut members = Vec::new();
        members
            .try_reserve_exact(channel.memberships.len())
            .map_err(|_| DomainError::AllocationFailed)?;
        for membership in channel.memberships.values() {
            if self
                .sessions
                .get(&membership.user_id)
                .is_some_and(|session| {
                    self.fenced_federation_peers
                        .contains(&session.home_server_id)
                })
            {
                continue;
            }
            let Some(session) = self.session(membership.user_id) else {
                return Err(DomainError::InvariantViolation);
            };
            members.push(MemberProjection {
                user_id: membership.user_id,
                nickname: &session.nickname,
                display_name: &session.display_name,
                role: membership.effective_role,
            });
        }
        Ok(ProjectionDecision::Visible(ChannelProjection {
            channel_id,
            name: &channel.name,
            visibility: channel.visibility,
            topic: topic_projection(channel),
            members,
        }))
    }

    /// Returns at most 200 listed channels with only privacy-bucketed counts.
    pub fn project_channel_list(&self) -> Result<Vec<ChannelListProjection<'_>>, DomainError> {
        let listed_count = self
            .channels
            .values()
            .filter(|channel| channel.visibility == Visibility::Listed)
            .count()
            .min(MAX_LIST_RESULTS);
        let mut projections = Vec::new();
        projections
            .try_reserve_exact(listed_count)
            .map_err(|_| DomainError::AllocationFailed)?;
        for channel in self
            .channels
            .values()
            .filter(|channel| channel.visibility == Visibility::Listed)
            .take(MAX_LIST_RESULTS)
        {
            projections.push(ChannelListProjection {
                channel_id: channel.channel_id,
                name: &channel.name,
                member_count_lower_bound: member_bucket(
                    channel
                        .memberships
                        .keys()
                        .filter(|user| self.session(**user).is_some())
                        .count(),
                ),
                topic: topic_projection(channel),
            });
        }
        Ok(projections)
    }

    fn session_projection<'a>(
        &'a self,
        requester: UserId,
        session: &'a SessionState,
    ) -> SessionProjection<'a> {
        let account_label = session
            .account_id
            .and_then(|account_id| self.accounts.get(&account_id))
            .and_then(|account| account.label.as_ref());
        SessionProjection {
            user_id: session.user_id,
            nickname: &session.nickname,
            display_name: &session.display_name,
            public_cloak: session.public_cloak,
            account_label,
            away_text: (requester == session.user_id
                || self.shares_channel(requester, session.user_id))
            .then(|| session.away.as_ref().map(|away| away.as_str()))
            .flatten(),
        }
    }

    fn session_is_visible(&self, requester: UserId, target: &SessionState) -> bool {
        if requester == target.user_id || self.shares_channel(requester, target.user_id) {
            return true;
        }
        let Some(target_account_id) = target.account_id else {
            return false;
        };
        let Some(target_account) = self.accounts.get(&target_account_id) else {
            return false;
        };
        target_account.presence == PresencePolicy::Public
            || self.are_mutual_contacts(requester, target_account_id)
    }

    fn shares_channel(&self, left: UserId, right: UserId) -> bool {
        let (Some(left), Some(right)) = (self.session(left), self.session(right)) else {
            return false;
        };
        left.joined_channels
            .iter()
            .any(|channel_id| right.joined_channels.contains(channel_id))
    }

    fn are_mutual_contacts(&self, requester: UserId, target: AccountId) -> bool {
        let Some(requester_account_id) = self
            .session(requester)
            .and_then(|session| session.account_id)
        else {
            return false;
        };
        let Some(requester_account) = self.accounts.get(&requester_account_id) else {
            return false;
        };
        let Some(target_account) = self.accounts.get(&target) else {
            return false;
        };
        requester_account.contacts.contains(&target)
            && target_account.contacts.contains(&requester_account_id)
    }
}

fn topic_projection(channel: &crate::ChannelState) -> TopicProjection<'_> {
    match channel.content_policy {
        ContentPolicy::E2eeBound => TopicProjection::EncryptedPlaceholder,
        ContentPolicy::Plaintext => match &channel.topic {
            Some(topic) => TopicProjection::Plaintext(topic.text.as_str()),
            None => TopicProjection::None,
        },
    }
}

fn member_bucket(count: usize) -> u16 {
    match count {
        0 => 0,
        1 => 1,
        2..=4 => 2,
        5..=9 => 5,
        10..=24 => 10,
        25..=49 => 25,
        50..=99 => 50,
        _ => 100,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AccountLabelValue, AccountState, AwayText, ChannelState, DirectMessagePolicy,
        GuestDirectMessagePolicy, Membership, PlaintextTopic, Principal, SessionSeed, TopicText,
    };
    use agenc_ircd_types::{
        AccountRandomId, ControlPolicy, Generation, MessageId, Revision, ServerId, SessionId,
        UtcSecond,
    };

    fn bytes(seed: u8) -> [u8; 16] {
        [seed; 16]
    }

    fn account_id(seed: u8) -> AccountId {
        AccountId::from_random(AccountRandomId::from_bytes(bytes(seed)))
    }

    fn session(seed: u8, account_id: Option<AccountId>) -> Result<SessionState, DomainError> {
        Ok(SessionState::from_seed(SessionSeed {
            session_id: SessionId::from_bytes(bytes(seed)),
            user_id: UserId::from_bytes(bytes(seed.wrapping_add(64))),
            home_server_id: ServerId::from_bytes(bytes(240)),
            account_id,
            account_session_generation: Generation::new(u64::from(account_id.is_some()))?,
            generation: Generation::new(1)?,
            nickname: NicknameValue::parse(&format!("project{seed}"))?,
            display_name: DisplayNameValue::prepare(&format!("Project {seed}"))?,
            public_cloak: crate::model::test_public_cloak(seed)?,
            connection_nonce: [seed; 32],
            negotiated_capability_hash: [seed.wrapping_add(1); 32],
            created_at_utc: UtcSecond::from_unix_seconds(10),
            revision: Revision::new(1)?,
        }))
    }

    fn insert_session(state: &mut DomainState, session: SessionState) {
        state
            .session_ids
            .insert(session.session_id, session.user_id);
        state
            .nicknames
            .insert(session.nickname.clone(), session.user_id);
        state
            .public_cloaks
            .insert(session.public_cloak, session.user_id);
        state.sessions.insert(session.user_id, session);
    }

    #[test]
    fn account_and_session_projections_cover_hidden_public_and_contact_contexts()
    -> Result<(), DomainError> {
        let mut state = DomainState::new()?;
        let requester_account = account_id(1);
        let target_account = account_id(2);
        let requester = session(1, Some(requester_account))?;
        let target = session(2, Some(target_account))?;
        let guest = session(3, None)?;
        let requester_id = requester.user_id;
        let target_id = target.user_id;
        let guest_id = guest.user_id;

        assert!(matches!(
            state.project_account(requester_id, requester_account),
            ProjectionDecision::Hidden
        ));
        insert_session(&mut state, requester);
        assert!(matches!(
            state.project_account(requester_id, target_account),
            ProjectionDecision::Hidden
        ));
        assert!(matches!(
            state.project_account(requester_id, requester_account),
            ProjectionDecision::Hidden
        ));

        let mut requester_state =
            AccountState::new(requester_account, Generation::new(1)?, Revision::new(1)?);
        requester_state.guest_direct_messages = GuestDirectMessagePolicy::Deny;
        requester_state.direct_messages = DirectMessagePolicy::Contacts;
        state.accounts.insert(requester_account, requester_state);
        let ProjectionDecision::Visible(account) =
            state.project_account(requester_id, requester_account)
        else {
            return Err(DomainError::InvariantViolation);
        };
        assert_eq!(account.account_id(), requester_account);
        assert!(account.label().is_none());
        assert_eq!(account.presence(), PresencePolicy::Private);
        assert_eq!(
            account.guest_direct_messages(),
            GuestDirectMessagePolicy::Deny
        );
        assert_eq!(account.direct_messages(), DirectMessagePolicy::Contacts);

        insert_session(&mut state, target);
        insert_session(&mut state, guest);
        assert!(matches!(
            state.project_session(requester_id, UserId::from_bytes(bytes(250))),
            ProjectionDecision::Hidden
        ));
        assert!(matches!(
            state.project_session(requester_id, guest_id),
            ProjectionDecision::Hidden
        ));
        assert_eq!(
            state.project_presence(requester_id, target_id),
            PresenceProjection::Absent
        );

        let mut target_state =
            AccountState::new(target_account, Generation::new(1)?, Revision::new(1)?);
        target_state.presence = PresencePolicy::Public;
        state.accounts.insert(target_account, target_state);
        let ProjectionDecision::Visible(projected) = state.project_session(requester_id, target_id)
        else {
            return Err(DomainError::InvariantViolation);
        };
        assert_eq!(projected.user_id(), target_id);
        assert!(projected.account_label().is_none());
        assert_eq!(projected.away_text(), None);
        assert_eq!(
            state.project_presence(requester_id, target_id),
            PresenceProjection::Present
        );

        state
            .accounts
            .get_mut(&target_account)
            .ok_or(DomainError::InvariantViolation)?
            .presence = PresencePolicy::Private;
        assert!(!state.are_mutual_contacts(guest_id, target_account));
        state
            .accounts
            .get_mut(&requester_account)
            .ok_or(DomainError::InvariantViolation)?
            .contacts
            .insert(target_account);
        state
            .accounts
            .get_mut(&target_account)
            .ok_or(DomainError::InvariantViolation)?
            .contacts
            .insert(requester_account);
        assert!(state.are_mutual_contacts(requester_id, target_account));
        assert!(matches!(
            state.project_session(requester_id, target_id),
            ProjectionDecision::Visible(_)
        ));
        Ok(())
    }

    #[test]
    fn channel_projection_and_member_buckets_fail_closed_at_every_boundary()
    -> Result<(), DomainError> {
        for (count, expected) in [
            (0, 0),
            (1, 1),
            (2, 2),
            (4, 2),
            (5, 5),
            (9, 5),
            (10, 10),
            (24, 10),
            (25, 25),
            (49, 25),
            (50, 50),
            (99, 50),
            (100, 100),
        ] {
            assert_eq!(member_bucket(count), expected);
        }

        let mut state = DomainState::new()?;
        let requester = session(4, None)?;
        let requester_id = requester.user_id;
        insert_session(&mut state, requester);
        let channel_id = ChannelInstanceId::from_bytes(bytes(4));
        assert!(matches!(
            state.project_channel(requester_id, channel_id)?,
            ProjectionDecision::Hidden
        ));

        let missing_user = UserId::from_bytes(bytes(200));
        let mut channel = ChannelState::new_ephemeral(
            channel_id,
            ChannelNameValue::parse("#projection")?,
            Principal::Guest(missing_user),
            Membership::new(missing_user, None, Role::Owner),
            UtcSecond::from_unix_seconds(10),
            Revision::new(1)?,
        );
        channel.visibility = Visibility::Secret;
        state.channel_names.insert(channel.name.clone(), channel_id);
        state.channels.insert(channel_id, channel);
        assert!(matches!(
            state.project_channel(requester_id, channel_id)?,
            ProjectionDecision::Hidden
        ));

        state
            .channels
            .get_mut(&channel_id)
            .ok_or(DomainError::InvariantViolation)?
            .visibility = Visibility::Listed;
        assert_eq!(
            state.project_channel(requester_id, channel_id).err(),
            Some(DomainError::InvariantViolation)
        );
        let missing = session(136, None)?;
        let missing_id = missing.user_id;
        insert_session(&mut state, missing);
        let ProjectionDecision::Visible(projected) =
            state.project_channel(requester_id, channel_id)?
        else {
            return Err(DomainError::InvariantViolation);
        };
        assert_eq!(projected.channel_id(), channel_id);
        assert_eq!(projected.name().canonical(), "#projection");
        assert_eq!(projected.visibility(), Visibility::Listed);
        assert!(matches!(projected.topic(), TopicProjection::None));
        assert_eq!(projected.members().len(), 1);
        let member = projected
            .members()
            .first()
            .ok_or(DomainError::InvariantViolation)?;
        assert_eq!(member.user_id(), missing_id);
        assert_eq!(member.role(), Role::Owner);
        assert!(!state.shares_channel(UserId::from_bytes(bytes(251)), missing_id));
        Ok(())
    }

    #[test]
    fn session_context_and_topic_projection_cover_each_visibility_path() -> Result<(), DomainError>
    {
        let requester_account = account_id(20);
        let target_account = account_id(21);
        let requester = session(20, Some(requester_account))?;
        let mut target = session(21, Some(target_account))?;
        let requester_id = requester.user_id;
        let target_id = target.user_id;
        target.away = Some(AwayText::try_from_str("away", ControlPolicy::RejectAll)?);

        let mut state = DomainState::new()?;
        insert_session(&mut state, requester);
        insert_session(&mut state, target);
        assert!(matches!(
            state.project_session(requester_id, requester_id),
            ProjectionDecision::Visible(_)
        ));
        assert!(matches!(
            state.project_session(requester_id, target_id),
            ProjectionDecision::Hidden
        ));
        assert!(!state.are_mutual_contacts(requester_id, target_account));

        let mut target_state =
            AccountState::new(target_account, Generation::new(1)?, Revision::new(1)?);
        target_state.label = Some(AccountLabelValue::parse("Target")?);
        state.accounts.insert(target_account, target_state);
        assert!(!state.are_mutual_contacts(requester_id, target_account));

        let mut requester_state =
            AccountState::new(requester_account, Generation::new(1)?, Revision::new(1)?);
        requester_state.contacts.insert(target_account);
        state.accounts.insert(requester_account, requester_state);
        assert!(!state.are_mutual_contacts(requester_id, target_account));
        state
            .accounts
            .get_mut(&target_account)
            .ok_or(DomainError::InvariantViolation)?
            .contacts
            .insert(requester_account);
        assert!(state.are_mutual_contacts(requester_id, target_account));
        let ProjectionDecision::Visible(projected) = state.project_session(requester_id, target_id)
        else {
            return Err(DomainError::InvariantViolation);
        };
        assert_eq!(
            projected.account_label().map(AccountLabelValue::as_str),
            Some("Target")
        );
        assert_eq!(projected.away_text(), None);

        let shared_id = ChannelInstanceId::from_bytes(bytes(30));
        state
            .sessions
            .get_mut(&requester_id)
            .ok_or(DomainError::InvariantViolation)?
            .joined_channels
            .insert(shared_id);
        state
            .sessions
            .get_mut(&target_id)
            .ok_or(DomainError::InvariantViolation)?
            .joined_channels
            .insert(shared_id);
        assert!(state.shares_channel(requester_id, target_id));
        let ProjectionDecision::Visible(projected) = state.project_session(requester_id, target_id)
        else {
            return Err(DomainError::InvariantViolation);
        };
        assert_eq!(projected.away_text(), Some("away"));

        let mut channel = ChannelState::new_ephemeral(
            shared_id,
            ChannelNameValue::parse("#visible-secret")?,
            Principal::Account(requester_account),
            Membership::new(requester_id, Some(requester_account), Role::Owner),
            UtcSecond::from_unix_seconds(10),
            Revision::new(1)?,
        );
        channel.visibility = Visibility::Secret;
        channel.topic = Some(PlaintextTopic {
            text: TopicText::try_from_str("topic", ControlPolicy::RejectAll)?,
            message_id: MessageId::from_bytes(bytes(30)),
            setter: requester_id,
            set_at: UtcSecond::from_unix_seconds(10),
        });
        state.channel_names.insert(channel.name.clone(), shared_id);
        state.channels.insert(shared_id, channel);
        let ProjectionDecision::Visible(projected) =
            state.project_channel(requester_id, shared_id)?
        else {
            return Err(DomainError::InvariantViolation);
        };
        assert!(matches!(
            projected.topic(),
            TopicProjection::Plaintext("topic")
        ));

        let channel = state
            .channels
            .get_mut(&shared_id)
            .ok_or(DomainError::InvariantViolation)?;
        channel.visibility = Visibility::Listed;
        channel.content_policy = ContentPolicy::E2eeBound;
        assert!(matches!(
            state
                .project_channel_list()?
                .first()
                .map(ChannelListProjection::topic),
            Some(TopicProjection::EncryptedPlaceholder)
        ));
        Ok(())
    }

    #[test]
    fn mutual_contact_guard_matrix_hides_every_incomplete_authority_chain()
    -> Result<(), DomainError> {
        let requester_account = account_id(40);
        let target_account = account_id(41);
        let requester = session(40, Some(requester_account))?;
        let guest = session(42, None)?;
        let target = session(41, Some(target_account))?;
        let requester_id = requester.user_id;
        let guest_id = guest.user_id;
        let target_id = target.user_id;

        let mut state = DomainState::new()?;
        insert_session(&mut state, target);
        state.accounts.insert(
            target_account,
            AccountState::new(target_account, Generation::new(1)?, Revision::new(1)?),
        );
        assert!(
            !state.session_is_visible(
                UserId::from_bytes(bytes(250)),
                state
                    .sessions
                    .get(&target_id)
                    .ok_or(DomainError::InvariantViolation)?,
            )
        );

        insert_session(&mut state, guest);
        assert!(!state.are_mutual_contacts(guest_id, target_account));
        insert_session(&mut state, requester);
        assert!(!state.are_mutual_contacts(requester_id, target_account));
        state.accounts.insert(
            requester_account,
            AccountState::new(requester_account, Generation::new(1)?, Revision::new(1)?),
        );
        assert!(!state.are_mutual_contacts(requester_id, account_id(99)));
        assert!(!state.are_mutual_contacts(requester_id, target_account));
        assert!(!state.shares_channel(requester_id, target_id));
        assert!(!state.shares_channel(requester_id, UserId::from_bytes(bytes(251)),));
        Ok(())
    }
}
