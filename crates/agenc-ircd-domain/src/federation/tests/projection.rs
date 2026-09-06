#![forbid(unsafe_code)]

//! Coordinator projection derivation driven through the real domain plans,
//! and the round trip of every derived delta into an edge replica.

use std::collections::BTreeMap;

use agenc_ircd_types::{
    ChannelInstanceId, ControlPolicy, EntryId, Generation, InviteId, MessageId, MonotonicTick,
    Revision, ServerId, SessionId, UserId, UtcSecond,
};

use super::*;
use crate::federation::record::{
    DeliveryTarget, EventPhase, ProjectedEvent, ProjectionKey, ProjectionRecord, SessionHideKind,
};
use crate::federation::replica::EdgeReplica;
use crate::model::test_public_cloak;
use crate::{
    AdmissionSnapshot, CanonicalCommand, ChannelNameValue, ChannelTarget, CommandEnvelope,
    DepartureReason, DisplayNameValue, DomainError, DomainState, EntropyPurpose,
    ExternalInputRequest, ExternalInputs, MessageCommand, MessageKind, MessageTarget, MessageText,
    NicknameValue, PlanDecision, RateBucket, SessionSeed, TopicText,
};

const LOCAL: ServerId = ServerId::from_bytes([200; 16]);
const EDGE_A: ServerId = ServerId::from_bytes([10; 16]);
const EDGE_B: ServerId = ServerId::from_bytes([11; 16]);

struct Harness {
    state: DomainState,
    index: CoordinatorProjection,
    replicas: BTreeMap<ServerId, EdgeReplica>,
    next_id: u8,
}

impl Harness {
    fn new() -> Result<Self, DomainError> {
        let mut replicas = BTreeMap::new();
        replicas.insert(EDGE_A, EdgeReplica::new(EDGE_A));
        replicas.insert(EDGE_B, EdgeReplica::new(EDGE_B));
        Ok(Self {
            state: DomainState::new()?,
            index: CoordinatorProjection::new(LOCAL),
            replicas,
            next_id: 100,
        })
    }

    fn fresh_id(&mut self) -> [u8; 16] {
        self.next_id = self.next_id.wrapping_add(1);
        [self.next_id; 16]
    }

    fn seed(&self, n: u8, home: ServerId) -> Result<SessionSeed, DomainError> {
        Ok(SessionSeed {
            session_id: SessionId::from_bytes([n; 16]),
            user_id: UserId::from_bytes([n.wrapping_add(64); 16]),
            home_server_id: home,
            account_id: None,
            account_session_generation: Generation::new(0)?,
            generation: Generation::new(1)?,
            nickname: NicknameValue::parse(&format!("user{n}"))?,
            display_name: DisplayNameValue::prepare(&format!("User {n}"))?,
            public_cloak: test_public_cloak(n)?,
            connection_nonce: [n; 32],
            negotiated_capability_hash: [n.wrapping_add(1); 32],
            created_at_utc: UtcSecond::from_unix_seconds(10),
            revision: self.state.revision(),
        })
    }

    /// Applies one plan, derives its projection, commits it to the index,
    /// and applies every event copy to the matching replica.
    fn commit(
        &mut self,
        plan: crate::MutationPlan,
        context: &MutationContext,
    ) -> Result<MutationProjection, DomainError> {
        let projection = self.index.derive(&self.state, &plan, context)?;
        let prepared = self.state.prepare_mutation(plan)?;
        let receipt = self.state.apply_prepared(prepared)?;
        self.index.apply(&projection);
        for delta in &projection.edges {
            let replica = self
                .replicas
                .get_mut(&delta.target)
                .ok_or(DomainError::NotFound)?;
            for event in &delta.events {
                replica
                    .apply(event, receipt.revision().get())
                    .map_err(|_| DomainError::InvariantViolation)?;
            }
            replica
                .validate()
                .map_err(|_| DomainError::InvariantViolation)?;
            let standing = self.index.edge(delta.target).ok_or(DomainError::NotFound)?;
            let replica_keys: Vec<ProjectionKey> =
                replica.entries().map(|entry| entry.key()).collect();
            let mut index_keys: Vec<ProjectionKey> = standing.keys().collect();
            index_keys.sort();
            let mut sorted_replica = replica_keys.clone();
            sorted_replica.sort();
            assert_eq!(sorted_replica, index_keys, "replica and index keys differ");
            // The snapshot cut derived from the live state must equal what
            // the incremental events built on the edge, record for record.
            let cut = CoordinatorProjection::standing_of(&self.state, delta.target);
            let cut_keys: Vec<ProjectionKey> = cut.iter().map(ProjectionRecord::key).collect();
            let mut replica_entries: Vec<ProjectionRecord> = replica.entries().collect();
            replica_entries.sort_by_key(ProjectionRecord::key);
            assert_eq!(
                cut_keys, index_keys,
                "snapshot cut keys differ from the index"
            );
            assert!(
                cut == replica_entries,
                "snapshot cut records differ from the replica"
            );
        }
        Ok(projection)
    }

    fn open(&mut self, n: u8, home: ServerId) -> Result<UserId, DomainError> {
        let seed = self.seed(n, home)?;
        let user = seed.user_id;
        let plan = self.state.plan_session_opened(seed)?;
        self.commit(plan, &MutationContext::default())?;
        Ok(user)
    }

    fn run(
        &mut self,
        user: UserId,
        build: impl Fn() -> Result<CanonicalCommand, DomainError>,
        context: &MutationContext,
    ) -> Result<MutationProjection, DomainError> {
        let session = self.state.session(user).ok_or(DomainError::NotFound)?;
        let envelope = CommandEnvelope::new(
            session.session_id(),
            user,
            session.generation(),
            self.state.revision(),
            build()?,
        );
        let mut entries: Vec<(RateBucket, u64)> = self
            .state
            .command_charges(user, envelope.command())
            .iter()
            .map(|charge| (charge.bucket(), 10))
            .collect();
        entries.sort_by_key(|(bucket, _)| format!("{bucket:?}"));
        entries.dedup_by_key(|(bucket, _)| format!("{bucket:?}"));
        let credit = AdmissionSnapshot::new(entries)?;
        let authorized = self
            .state
            .authorize(envelope, &credit)
            .map_err(|failure| failure.error())?;
        let decision = self.state.plan_authorized(authorized, None)?;
        let plan = match decision {
            PlanDecision::Mutation(plan) => plan,
            PlanDecision::NeedsExternal(requests) => {
                let mut inputs = ExternalInputs::default();
                for request in &requests {
                    match request {
                        ExternalInputRequest::UtcNow { .. } => {
                            inputs.utc_now = Some(UtcSecond::from_unix_seconds(20));
                        }
                        ExternalInputRequest::MonotonicNow { .. } => {
                            inputs.monotonic_now = Some(MonotonicTick::from_ticks(20));
                        }
                        ExternalInputRequest::Entropy { purpose, .. } => match purpose {
                            EntropyPurpose::ChannelInstance(_) => inputs
                                .channel_ids
                                .push(ChannelInstanceId::from_bytes(self.fresh_id())),
                            EntropyPurpose::Message(_) => {
                                inputs
                                    .message_ids
                                    .push(MessageId::from_bytes(self.fresh_id()));
                            }
                            EntropyPurpose::Invite => {
                                inputs
                                    .invite_ids
                                    .push(InviteId::from_bytes(self.fresh_id()));
                            }
                            EntropyPurpose::MaskEntry(_) => {
                                inputs.entry_ids.push(EntryId::from_bytes(self.fresh_id()));
                            }
                            EntropyPurpose::AccountDeletionChallenge => {
                                return Err(DomainError::InvariantViolation);
                            }
                        },
                        ExternalInputRequest::ChannelKeyVerification { .. }
                        | ExternalInputRequest::ChannelKeyConstruction { .. } => {
                            return Err(DomainError::InvariantViolation);
                        }
                    }
                }
                let session = self.state.session(user).ok_or(DomainError::NotFound)?;
                let envelope = CommandEnvelope::new(
                    session.session_id(),
                    user,
                    session.generation(),
                    self.state.revision(),
                    build()?,
                );
                let authorized = self
                    .state
                    .authorize(envelope, &credit)
                    .map_err(|failure| failure.error())?;
                match self.state.plan_authorized(authorized, Some(inputs))? {
                    PlanDecision::Mutation(plan) => plan,
                    _ => return Err(DomainError::InvariantViolation),
                }
            }
            PlanDecision::Query(_) | PlanDecision::Rejected(_) => {
                return Err(DomainError::InvariantViolation);
            }
        };
        self.commit(plan, context)
    }
}

fn events_for(projection: &MutationProjection, edge: ServerId) -> Vec<&ProjectedEvent> {
    projection
        .edges
        .iter()
        .find(|delta| delta.target == edge)
        .map(|delta| delta.events.iter().collect())
        .unwrap_or_default()
}

fn kinds(events: &[&ProjectedEvent]) -> Vec<agenc_ircd_types::FederationEventKind> {
    events.iter().map(|event| event.kind()).collect()
}

#[test]
fn sessions_channels_messages_and_departures_project_least_information() -> Result<(), DomainError>
{
    use agenc_ircd_types::FederationEventKind as K;
    let mut harness = Harness::new()?;
    let alice = harness.open(1, EDGE_A)?;
    let bob = harness.open(2, EDGE_B)?;
    let standing_a = harness.index.edge(EDGE_A).ok_or(DomainError::NotFound)?;
    assert_eq!(standing_a.entry_count(), 1);
    assert!(
        harness
            .replicas
            .get(&EDGE_A)
            .and_then(|replica| replica.session(alice))
            .is_some()
    );
    assert!(
        harness
            .replicas
            .get(&EDGE_B)
            .and_then(|replica| replica.session(alice))
            .is_none()
    );

    let name = ChannelNameValue::parse("#room")?;
    let join = || CanonicalCommand::join(vec![ChannelTarget::new(name.clone(), false)]);
    let projection = harness.run(alice, join, &MutationContext::default())?;
    let to_a = events_for(&projection, EDGE_A);
    assert_eq!(kinds(&to_a), vec![K::ChannelVisible, K::MemberJoined]);
    assert!(events_for(&projection, EDGE_B).is_empty());
    let channel_id = harness
        .state
        .resolve_channel(&name)
        .ok_or(DomainError::NotFound)?;
    assert!(
        harness
            .index
            .edge(EDGE_A)
            .is_some_and(|standing| standing.holds_channel(channel_id))
    );
    let replica_a = harness.replicas.get(&EDGE_A).ok_or(DomainError::NotFound)?;
    assert_eq!(
        replica_a.local_members(channel_id).collect::<Vec<_>>(),
        vec![alice]
    );
    assert_eq!(
        replica_a
            .channel(channel_id)
            .map(|detail| detail.channel_revision),
        Some(harness.state.revision())
    );

    let projection = harness.run(bob, join, &MutationContext::default())?;
    assert_eq!(
        kinds(&events_for(&projection, EDGE_A)),
        vec![K::MemberJoined]
    );
    assert_eq!(
        kinds(&events_for(&projection, EDGE_B)),
        vec![K::ChannelVisible, K::MemberJoined]
    );
    let Some(ProjectedEvent::MemberJoined {
        home_session_revision,
        ..
    }) = events_for(&projection, EDGE_A).first().copied()
    else {
        return Err(DomainError::InvariantViolation);
    };
    assert_eq!(*home_session_revision, None);
    let Some(ProjectedEvent::MemberJoined {
        home_session_revision,
        ..
    }) = events_for(&projection, EDGE_B).get(1).copied()
    else {
        return Err(DomainError::InvariantViolation);
    };
    assert_eq!(*home_session_revision, Some(harness.state.revision()));

    let message = || {
        Ok(CanonicalCommand::message(MessageCommand::new(
            MessageKind::Privmsg,
            vec![MessageTarget::Channel(name.clone())],
            Some(MessageText::parse("hello")?),
        )?))
    };
    let context = MutationContext {
        received_unix_milliseconds: 1_234,
        ..MutationContext::default()
    };
    let projection = harness.run(alice, message, &context)?;
    for edge in [EDGE_A, EDGE_B] {
        let events = events_for(&projection, edge);
        let Some(ProjectedEvent::MessageDelivered(record)) = events.first().copied() else {
            return Err(DomainError::InvariantViolation);
        };
        assert_eq!(
            record.channel_event_sequence,
            harness.state.revision().get()
        );
        assert_eq!(record.target, DeliveryTarget::Channel(channel_id));
        assert_eq!(record.body, "hello");
        assert_eq!(record.received_unix_milliseconds, 1_234);
        assert_eq!(record.sender.user_id, alice);
    }

    let topic = || {
        Ok(CanonicalCommand::topic_set(
            name.clone(),
            TopicText::try_from_str("welcome", ControlPolicy::RejectAll)?,
        ))
    };
    let context = MutationContext {
        actor: Some(alice),
        ..MutationContext::default()
    };
    let projection = harness.run(alice, topic, &context)?;
    assert_eq!(
        kinds(&events_for(&projection, EDGE_B)),
        vec![K::TopicChanged]
    );

    let part = || {
        CanonicalCommand::part(
            vec![name.clone()],
            Some(DepartureReason::try_from_str(
                "bye",
                ControlPolicy::RejectAll,
            )?),
        )
    };
    let context = MutationContext {
        reason: "bye".to_owned(),
        ..MutationContext::default()
    };
    let projection = harness.run(bob, part, &context)?;
    assert_eq!(
        kinds(&events_for(&projection, EDGE_A)),
        vec![K::MemberParted]
    );
    assert_eq!(
        kinds(&events_for(&projection, EDGE_B)),
        vec![K::MemberParted, K::ChannelHidden]
    );
    assert!(
        harness
            .index
            .edge(EDGE_B)
            .is_some_and(|standing| !standing.holds_channel(channel_id))
    );
    assert!(
        harness
            .replicas
            .get(&EDGE_B)
            .and_then(|replica| replica.channel(channel_id))
            .is_none()
    );
    let phases: Vec<EventPhase> = events_for(&projection, EDGE_B)
        .iter()
        .map(|event| event.phase())
        .collect();
    assert_eq!(phases, vec![EventPhase::Named, EventPhase::Hidden]);

    let plan = harness.state.plan_session_disconnected(alice)?;
    let context = MutationContext {
        hide_kind: Some(SessionHideKind::TransportLost),
        ..MutationContext::default()
    };
    let projection = harness.commit(plan, &context)?;
    let to_a = events_for(&projection, EDGE_A);
    assert_eq!(kinds(&to_a), vec![K::SessionHidden, K::ChannelDestroyed]);
    let Some(ProjectedEvent::SessionHidden {
        channels,
        kind,
        reason,
        ..
    }) = to_a.first().copied()
    else {
        return Err(DomainError::InvariantViolation);
    };
    assert_eq!(channels.len(), 1);
    assert_eq!(*kind, SessionHideKind::TransportLost);
    assert_eq!(reason, "connection lost");
    assert!(events_for(&projection, EDGE_B).is_empty());
    let replica_a = harness.replicas.get(&EDGE_A).ok_or(DomainError::NotFound)?;
    assert_eq!(replica_a.entry_count(), 0);
    assert_eq!(
        harness.index.edge(EDGE_A).map(EdgeStanding::entry_count),
        Some(0)
    );
    assert_eq!(projection.event_count(), 2);
    Ok(())
}

#[test]
fn nickname_and_away_changes_reach_home_and_shared_edges_only() -> Result<(), DomainError> {
    use agenc_ircd_types::FederationEventKind as K;
    let mut harness = Harness::new()?;
    let alice = harness.open(1, EDGE_A)?;
    let bob = harness.open(2, EDGE_B)?;
    let _carol = harness.open(3, LOCAL)?;
    let nick = || Ok(CanonicalCommand::nick(NicknameValue::parse("alice2")?));
    let projection = harness.run(alice, nick, &MutationContext::default())?;
    assert_eq!(
        kinds(&events_for(&projection, EDGE_A)),
        vec![K::NicknameChanged]
    );
    assert!(events_for(&projection, EDGE_B).is_empty());
    assert!(projection.edges.iter().all(|delta| delta.target != LOCAL));

    let name = ChannelNameValue::parse("#shared")?;
    for user in [alice, bob] {
        let join = || CanonicalCommand::join(vec![ChannelTarget::new(name.clone(), false)]);
        harness.run(user, join, &MutationContext::default())?;
    }
    let nick = || Ok(CanonicalCommand::nick(NicknameValue::parse("alice3")?));
    let projection = harness.run(alice, nick, &MutationContext::default())?;
    let to_b = events_for(&projection, EDGE_B);
    assert_eq!(kinds(&to_b), vec![K::NicknameChanged]);
    let Some(ProjectedEvent::NicknameChanged { old_nickname, view }) = to_b.first().copied() else {
        return Err(DomainError::InvariantViolation);
    };
    assert_eq!(old_nickname.canonical(), "alice2");
    assert!(view.home_projection.is_none());
    let to_a = events_for(&projection, EDGE_A);
    let Some(ProjectedEvent::NicknameChanged { view, .. }) = to_a.first().copied() else {
        return Err(DomainError::InvariantViolation);
    };
    assert!(view.home_projection.is_some());
    assert_eq!(
        harness
            .replicas
            .get(&EDGE_A)
            .and_then(|replica| replica.session(alice))
            .map(|session| session.nickname.canonical().to_owned()),
        Some("alice3".to_owned())
    );

    let standing = harness.index.edge(EDGE_A).ok_or(DomainError::NotFound)?;
    let keys: Vec<ProjectionKey> = standing.keys().collect();
    assert_eq!(keys.len(), 3);
    let records: Vec<ProjectionRecord> = harness
        .replicas
        .get(&EDGE_A)
        .ok_or(DomainError::NotFound)?
        .entries()
        .collect();
    assert_eq!(records.len(), 3);
    Ok(())
}

#[test]
fn mode_bits_and_user_bits_follow_the_registered_layout() {
    let modes = crate::ChannelModes {
        invite_only: true,
        moderated: false,
        topic_protected: true,
        join_key: false,
    };
    assert_eq!(
        simple_mode_bits(modes, crate::Visibility::Listed),
        0b10_0101
    );
    assert_eq!(
        simple_mode_bits(modes, crate::Visibility::Unlisted),
        0b10_1101
    );
    assert_eq!(
        simple_mode_bits(modes, crate::Visibility::Secret),
        0b11_0101
    );
    assert_eq!(user_mode_bits(false), 1);
    assert_eq!(user_mode_bits(true), 3);
    assert_eq!(prefix_code(Role::Member), None);
    assert_eq!(prefix_code(Role::Owner), Some(12));
    assert_eq!(prefix_code(Role::Voice), Some(16));
}

#[test]
fn standing_keys_round_trip_through_removal() -> Result<(), DomainError> {
    let mut standing = EdgeStanding::default();
    let channel = ChannelInstanceId::from_bytes([1; 16]);
    let user = UserId::from_bytes([2; 16]);
    let invite = InviteId::from_bytes([3; 16]);
    let account = agenc_ircd_types::AccountId::from_random(
        agenc_ircd_types::AccountRandomId::from_bytes([4; 16]),
    );
    let detail = ChannelDetailRecord {
        channel_id: channel,
        name: ChannelNameValue::parse("#k")?,
        channel_revision: Revision::new(1)?,
        visibility: crate::Visibility::Listed,
        content_policy: crate::ContentPolicy::Plaintext,
        persistence: crate::PersistencePolicy::Ephemeral,
        simple_mode_bits: 4,
        history: crate::HistoryPolicy::Off,
        e2ee_route_binding: None,
    };
    standing.insert(&ProjectionRecord::ChannelDetail(detail));
    standing.insert(&ProjectionRecord::Membership(MembershipRecord {
        channel_id: channel,
        user_id: user,
        role: Role::Member,
        membership_revision: Revision::new(1)?,
        joined_at: UtcSecond::from_unix_seconds(1),
    }));
    standing.insert(&ProjectionRecord::Invite(InviteRecord {
        channel_id: channel,
        invite_id: invite,
        target: Principal::Guest(user),
        inviter_user_id: user,
        creation_revision: Revision::new(1)?,
        expires_at: UtcSecond::from_unix_seconds(2),
    }));
    standing.insert(&ProjectionRecord::Account(AccountRecord {
        account_id: account,
        account_session_generation: Generation::new(1)?,
        account_revision: Revision::new(1)?,
    }));
    assert_eq!(standing.entry_count(), 4);
    assert!(standing.holds_invite(channel, invite));
    assert!(standing.holds_account(account));
    assert!(standing.remove(&ProjectionKey::membership(channel, user)));
    assert!(standing.remove(&ProjectionKey::invite(channel, invite)));
    assert!(standing.remove(&ProjectionKey::account(account)));
    assert!(standing.remove(&ProjectionKey::channel_detail(channel)));
    assert!(!standing.remove(&ProjectionKey::session(user)));
    assert_eq!(standing.entry_count(), 0);
    Ok(())
}

/// Registers an account for `user` and switches the open session onto it,
/// returning the account id. Home and shared edges observe the authority
/// change and the account state.
impl Harness {
    fn register(
        &mut self,
        user: UserId,
        seed: u8,
    ) -> Result<agenc_ircd_types::AccountId, DomainError> {
        let account_id = agenc_ircd_types::AccountId::from_random(
            agenc_ircd_types::AccountRandomId::from_bytes([seed; 16]),
        );
        let account =
            crate::AccountState::new(account_id, Generation::new(1)?, self.state.revision());
        let plan = self.state.plan_account_created(account)?;
        self.commit(plan, &MutationContext::default())?;
        let session = self.state.session(user).ok_or(DomainError::NotFound)?;
        let plan = self.state.plan_session_account_switch(
            user,
            session.generation(),
            Some((account_id, Generation::new(1)?)),
        )?;
        self.commit(plan, &MutationContext::default())?;
        Ok(account_id)
    }
}

#[test]
fn account_switch_back_to_guest_hides_the_account_projection() -> Result<(), DomainError> {
    let mut harness = Harness::new()?;
    let alice = harness.open(1, EDGE_A)?;
    let account_id = harness.register(alice, 41)?;
    assert!(
        harness
            .index
            .edge(EDGE_A)
            .is_some_and(|standing| standing.holds_account(account_id))
    );
    let session = harness.state.session(alice).ok_or(DomainError::NotFound)?;
    let plan = harness
        .state
        .plan_session_account_switch(alice, session.generation(), None)?;
    harness.commit(plan, &MutationContext::default())?;
    assert!(
        harness
            .index
            .edge(EDGE_A)
            .is_some_and(|standing| !standing.holds_account(account_id))
    );
    assert!(
        harness
            .replicas
            .get(&EDGE_A)
            .and_then(|replica| replica.account(account_id))
            .is_none()
    );
    Ok(())
}

#[test]
fn away_and_display_name_reach_home_and_shared_edges() -> Result<(), DomainError> {
    use agenc_ircd_types::FederationEventKind as K;
    let mut harness = Harness::new()?;
    let alice = harness.open(1, EDGE_A)?;
    let bob = harness.open(2, EDGE_B)?;
    let name = ChannelNameValue::parse("#room")?;
    for user in [alice, bob] {
        let join = || CanonicalCommand::join(vec![ChannelTarget::new(name.clone(), false)]);
        harness.run(user, join, &MutationContext::default())?;
    }
    let away = || {
        crate::CanonicalCommand::presence(crate::PresenceCommand::Away(Some(
            crate::AwayText::try_from_str("brb", ControlPolicy::RejectAll)?,
        )))
    };
    let projection = harness.run(alice, away, &MutationContext::default())?;
    assert_eq!(
        kinds(&events_for(&projection, EDGE_B)),
        vec![K::AwayChanged]
    );
    assert_eq!(
        kinds(&events_for(&projection, EDGE_A)),
        vec![K::AwayChanged]
    );

    let setname = || {
        Ok(CanonicalCommand::setname(DisplayNameValue::prepare(
            "Alice A.",
        )?))
    };
    let projection = harness.run(alice, setname, &MutationContext::default())?;
    assert_eq!(
        kinds(&events_for(&projection, EDGE_B)),
        vec![K::DisplayNameChanged]
    );
    Ok(())
}

#[test]
fn kicks_and_mode_changes_project_to_member_edges() -> Result<(), DomainError> {
    use crate::{ModeChange, ModeOperation};
    use agenc_ircd_types::FederationEventKind as K;
    let mut harness = Harness::new()?;
    let alice = harness.open(1, EDGE_A)?;
    let bob = harness.open(2, EDGE_B)?;
    let name = ChannelNameValue::parse("#ops")?;
    for user in [alice, bob] {
        let join = || CanonicalCommand::join(vec![ChannelTarget::new(name.clone(), false)]);
        harness.run(user, join, &MutationContext::default())?;
    }
    // Alice, the channel owner, grants Bob voice, then removes it.
    let grant = {
        let name = name.clone();
        let target = harness
            .state
            .session(bob)
            .ok_or(DomainError::NotFound)?
            .nickname()
            .clone();
        move || {
            CanonicalCommand::mode(
                name.clone(),
                vec![ModeChange::Role {
                    operation: ModeOperation::Add,
                    role: Role::Voice,
                    target: target.clone(),
                }],
            )
        }
    };
    let context = MutationContext {
        actor: Some(alice),
        ..MutationContext::default()
    };
    let projection = harness.run(alice, grant, &context)?;
    assert!(kinds(&events_for(&projection, EDGE_B)).contains(&K::ChannelModesChanged));

    // Alice kicks Bob; both edges observe the removal.
    let kick = {
        let name = name.clone();
        let target = harness
            .state
            .session(bob)
            .ok_or(DomainError::NotFound)?
            .nickname()
            .clone();
        move || {
            CanonicalCommand::kick(
                name.clone(),
                vec![target.clone()],
                Some(DepartureReason::try_from_str(
                    "out",
                    ControlPolicy::RejectAll,
                )?),
            )
        }
    };
    let context = MutationContext {
        actor: Some(alice),
        reason: "out".to_owned(),
        ..MutationContext::default()
    };
    let projection = harness.run(alice, kick, &context)?;
    assert!(kinds(&events_for(&projection, EDGE_B)).contains(&K::MemberParted));
    let channel_id = harness
        .state
        .resolve_channel(&name)
        .ok_or(DomainError::NotFound)?;
    assert!(
        harness
            .replicas
            .get(&EDGE_B)
            .and_then(|replica| replica.channel(channel_id))
            .is_none()
    );
    Ok(())
}

#[test]
fn resync_expiry_hides_retained_sessions_from_presence_and_membership_queries()
-> Result<(), DomainError> {
    let mut harness = Harness::new()?;
    let alice = harness.open(1, EDGE_A)?;
    let bob = harness.open(2, EDGE_B)?;
    let name = ChannelNameValue::parse("#room")?;
    let join = || CanonicalCommand::join(vec![ChannelTarget::new(name.clone(), false)]);
    harness.run(alice, join, &MutationContext::default())?;
    harness.run(bob, join, &MutationContext::default())?;
    let channel = harness
        .state
        .resolve_channel(&name)
        .ok_or(DomainError::NotFound)?;
    harness.state.fence_federation_peer(EDGE_A);
    assert_eq!(
        harness.state.project_presence(bob, alice),
        crate::PresenceProjection::Absent
    );
    assert_eq!(
        harness
            .state
            .resolve_nickname(&NicknameValue::parse("user1")?),
        None
    );
    assert!(!harness.state.session_user_ids().any(|user| user == alice));
    let crate::ProjectionDecision::Visible(view) = harness.state.project_channel(bob, channel)?
    else {
        return Err(DomainError::InvariantViolation);
    };
    assert_eq!(
        view.members().len(),
        1,
        "the physical membership is absent behind the peer fence"
    );
    assert!(
        harness.state.durable_session(alice).is_some(),
        "cleanup still needs the retained row"
    );
    Ok(())
}
