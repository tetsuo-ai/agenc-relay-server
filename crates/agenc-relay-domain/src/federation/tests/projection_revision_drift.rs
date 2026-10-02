//! Every coordinator mutation that advances a channel's revision reaches each
//! edge holding that channel, so the next channel message binds to the
//! revision the edge installed. A principal that stops being hosted on an
//! edge, by closing, logging in or logging out, takes its invite copies along.
#![forbid(unsafe_code)]

use super::*;
use crate::federation::replica::ReplicaError;
use agenc_relay_types::{AccountId, FederationEventKind as K};

const EDGE_C: ServerId = ServerId::from_bytes([12; 16]);
const EDGES: [ServerId; 3] = [EDGE_A, EDGE_B, EDGE_C];

fn room() -> Result<ChannelNameValue, DomainError> {
    ChannelNameValue::parse("#room")
}

fn three_edges() -> Result<Harness, DomainError> {
    let mut harness = Harness::new()?;
    harness.replicas.insert(EDGE_C, EdgeReplica::new(EDGE_C));
    Ok(harness)
}

fn join(harness: &mut Harness, user: UserId) -> Result<(), DomainError> {
    let name = room()?;
    let join = || CanonicalCommand::join(vec![ChannelTarget::new(name.clone(), false)]);
    harness.run(user, join, &MutationContext::default())?;
    Ok(())
}

/// Applies every event copy of one projection and reports each edge's first
/// refusal instead of hiding it behind a domain error.
fn replicate(
    harness: &mut Harness,
    projection: &MutationProjection,
    revision: Revision,
) -> Result<[Result<(), ReplicaError>; 3], DomainError> {
    let mut outcomes = [Ok(()), Ok(()), Ok(())];
    for (edge, outcome) in EDGES.iter().zip(outcomes.iter_mut()) {
        let replica = harness
            .replicas
            .get_mut(edge)
            .ok_or(DomainError::NotFound)?;
        *outcome = events_for(projection, *edge)
            .into_iter()
            .try_for_each(|event| replica.apply(event, revision.get()).map(|_| ()))
            .and_then(|()| replica.validate());
    }
    Ok(outcomes)
}

/// Commits one plan and returns the event kinds each edge received once
/// every replica accepted its copies.
fn deliver(harness: &mut Harness, plan: crate::MutationPlan) -> Result<[Vec<K>; 3], DomainError> {
    let (projection, revision) = harness.advance(plan, &MutationContext::default())?;
    assert_eq!(replicate(harness, &projection, revision)?, ACCEPTED);
    Ok(EDGES.map(|edge| kinds(&events_for(&projection, edge))))
}

fn say(harness: &mut Harness, user: UserId) -> Result<[Vec<K>; 3], DomainError> {
    let name = room()?;
    let message = || {
        Ok(CanonicalCommand::message(MessageCommand::new(
            MessageKind::Privmsg,
            vec![MessageTarget::Channel(name.clone())],
            Some(MessageText::parse("hello")?),
        )?))
    };
    let plan = harness.plan(user, message)?;
    deliver(harness, plan)
}

/// Each replica holds exactly the snapshot cut of the live state.
fn assert_replicas_match_the_cut(harness: &Harness) -> Result<(), DomainError> {
    for edge in EDGES {
        let replica = harness.replicas.get(&edge).ok_or(DomainError::NotFound)?;
        let mut entries: Vec<ProjectionRecord> = replica.entries().collect();
        entries.sort_by_key(ProjectionRecord::key);
        let cut = CoordinatorProjection::standing_of(&harness.state, edge);
        assert!(
            cut == entries,
            "snapshot cut records differ from the replica"
        );
    }
    Ok(())
}

const ACCEPTED: [Result<(), ReplicaError>; 3] = [Ok(()), Ok(()), Ok(())];

/// The kinds of one channel message delivered to exactly the named edges.
fn heard(edges: &[ServerId]) -> [Vec<K>; 3] {
    EDGES.map(|edge| {
        if edges.contains(&edge) {
            vec![K::MessageDelivered]
        } else {
            Vec::new()
        }
    })
}

#[test]
fn an_invite_hosted_elsewhere_advances_the_channel_on_every_member_edge() -> Result<(), DomainError>
{
    let mut harness = three_edges()?;
    let alice = harness.open(1, EDGE_A)?;
    let bob = harness.open(2, EDGE_A)?;
    harness.open(3, EDGE_B)?;
    let dave = harness.open(4, EDGE_C)?;
    for member in [alice, bob, dave] {
        join(&mut harness, member)?;
    }
    let name = room()?;
    let nickname = NicknameValue::parse("user3")?;
    let invite = || Ok(CanonicalCommand::invite(nickname.clone(), name.clone()));
    let plan = harness.plan(alice, invite)?;
    assert_eq!(
        deliver(&mut harness, plan)?,
        [
            vec![K::Invited],
            vec![K::ChannelVisible, K::Invited],
            vec![K::Invited]
        ]
    );
    assert_eq!(say(&mut harness, alice)?, heard(&[EDGE_A, EDGE_C]));
    assert_replicas_match_the_cut(&harness)?;
    assert_eq!(say(&mut harness, dave)?, heard(&[EDGE_A, EDGE_C]));
    Ok(())
}

fn create_account(harness: &mut Harness, seed: u8) -> Result<AccountId, DomainError> {
    let account_id =
        AccountId::from_random(agenc_relay_types::AccountRandomId::from_bytes([seed; 16]));
    let account =
        crate::AccountState::new(account_id, Generation::new(1)?, harness.state.revision());
    let plan = harness.state.plan_account_created(account)?;
    harness.commit(plan, &MutationContext::default())?;
    Ok(account_id)
}

fn switch(
    harness: &mut Harness,
    user: UserId,
    account: Option<AccountId>,
) -> Result<[Vec<K>; 3], DomainError> {
    let session = harness.state.session(user).ok_or(DomainError::NotFound)?;
    let account = match account {
        Some(account_id) => Some((account_id, Generation::new(1)?)),
        None => None,
    };
    let plan = harness
        .state
        .plan_session_account_switch(user, session.generation(), account)?;
    deliver(harness, plan)
}

#[test]
fn a_member_switching_account_advances_the_channel_on_every_member_edge() -> Result<(), DomainError>
{
    let mut harness = three_edges()?;
    let alice = harness.open(1, EDGE_A)?;
    let bob = harness.open(2, EDGE_B)?;
    let carol = harness.open(3, EDGE_C)?;
    for member in [alice, bob, carol] {
        join(&mut harness, member)?;
    }
    let account = create_account(&mut harness, 41)?;
    // The login also names the account to every member edge for
    // `account-notify`; the logout below does not.
    assert_eq!(
        switch(&mut harness, bob, Some(account))?,
        [
            vec![K::AccountLabelChanged, K::ChannelMembershipsRecomputed],
            vec![
                K::SessionVisible,
                K::AccountLabelChanged,
                K::AccountStateChanged,
                K::ChannelMembershipsRecomputed
            ],
            vec![K::AccountLabelChanged, K::ChannelMembershipsRecomputed]
        ]
    );
    assert_eq!(say(&mut harness, alice)?, heard(&EDGES));
    assert_replicas_match_the_cut(&harness)?;
    assert_eq!(
        switch(&mut harness, bob, None)?,
        [
            vec![K::ChannelMembershipsRecomputed],
            vec![K::SessionVisible, K::ChannelMembershipsRecomputed],
            vec![K::ChannelMembershipsRecomputed]
        ]
    );
    assert_eq!(say(&mut harness, bob)?, heard(&EDGES));
    assert_replicas_match_the_cut(&harness)?;
    Ok(())
}

fn invite_user(harness: &mut Harness, inviter: UserId, target: u8) -> Result<(), DomainError> {
    let name = room()?;
    let nickname = NicknameValue::parse(&format!("user{target}"))?;
    let invite = || Ok(CanonicalCommand::invite(nickname.clone(), name.clone()));
    harness.run(inviter, invite, &MutationContext::default())?;
    Ok(())
}

#[test]
fn a_closed_guest_leaves_no_invite_behind_on_its_home_edge() -> Result<(), DomainError> {
    let mut harness = three_edges()?;
    let alice = harness.open(1, EDGE_A)?;
    let bob = harness.open(2, EDGE_A)?;
    join(&mut harness, alice)?;
    invite_user(&mut harness, alice, 2)?;
    let plan = harness.state.plan_session_disconnected(bob)?;
    assert_eq!(
        deliver(&mut harness, plan)?,
        [
            vec![K::ChannelPolicyChanged, K::SessionHidden, K::InviteRemoved],
            Vec::new(),
            Vec::new()
        ]
    );
    assert_eq!(say(&mut harness, alice)?, heard(&[EDGE_A]));
    assert_replicas_match_the_cut(&harness)?;
    Ok(())
}

#[test]
fn a_closed_guest_invite_advances_the_channel_on_every_member_edge() -> Result<(), DomainError> {
    let mut harness = three_edges()?;
    let alice = harness.open(1, EDGE_A)?;
    let bob = harness.open(2, EDGE_B)?;
    let carol = harness.open(3, EDGE_C)?;
    join(&mut harness, alice)?;
    join(&mut harness, carol)?;
    invite_user(&mut harness, alice, 2)?;
    let plan = harness.state.plan_session_disconnected(bob)?;
    assert_eq!(
        deliver(&mut harness, plan)?,
        [
            vec![K::ChannelPolicyChanged],
            vec![K::SessionHidden, K::InviteRemoved, K::ChannelHidden],
            vec![K::ChannelPolicyChanged]
        ]
    );
    assert_eq!(say(&mut harness, carol)?, heard(&[EDGE_A, EDGE_C]));
    assert_replicas_match_the_cut(&harness)?;
    Ok(())
}

#[test]
fn an_expired_invite_advances_the_channel_on_edges_that_held_no_copy() -> Result<(), DomainError> {
    let mut harness = three_edges()?;
    let alice = harness.open(1, EDGE_A)?;
    harness.open(2, EDGE_B)?;
    let carol = harness.open(3, EDGE_C)?;
    join(&mut harness, alice)?;
    join(&mut harness, carol)?;
    invite_user(&mut harness, alice, 2)?;
    let plan = harness
        .state
        .plan_expired_invites(MonotonicTick::from_ticks(u64::MAX))?
        .ok_or(DomainError::NotFound)?;
    assert_eq!(
        deliver(&mut harness, plan)?,
        [
            vec![K::ChannelPolicyChanged],
            vec![K::InviteRemoved, K::ChannelHidden],
            vec![K::ChannelPolicyChanged]
        ]
    );
    assert_eq!(say(&mut harness, carol)?, heard(&[EDGE_A, EDGE_C]));
    assert_replicas_match_the_cut(&harness)?;
    Ok(())
}

#[test]
fn a_reprojected_invite_repeats_the_current_channel_revision() -> Result<(), DomainError> {
    let mut harness = three_edges()?;
    let alice = harness.open(1, EDGE_A)?;
    let bob = harness.open(2, EDGE_B)?;
    let carol = harness.open(3, EDGE_C)?;
    let account = harness.register(bob, 41)?;
    join(&mut harness, alice)?;
    invite_user(&mut harness, alice, 2)?;
    let name = room()?;
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
    harness.run(alice, topic, &context)?;
    // The login names the account to carol's home edge, which shares no
    // channel with anyone else yet.
    assert_eq!(
        switch(&mut harness, carol, Some(account))?,
        [
            Vec::new(),
            Vec::new(),
            vec![
                K::SessionVisible,
                K::ChannelVisible,
                K::AccountLabelChanged,
                K::AccountStateChanged,
                K::Invited
            ]
        ]
    );
    assert_replicas_match_the_cut(&harness)?;
    Ok(())
}

#[test]
fn a_guest_logging_in_leaves_no_guest_invite_behind() -> Result<(), DomainError> {
    let mut harness = three_edges()?;
    let alice = harness.open(1, EDGE_A)?;
    let bob = harness.open(2, EDGE_B)?;
    let carol = harness.open(3, EDGE_C)?;
    join(&mut harness, alice)?;
    join(&mut harness, carol)?;
    invite_user(&mut harness, alice, 2)?;
    let account = create_account(&mut harness, 41)?;
    // Bob is invited, not a member, so only his home edge learns the login.
    assert_eq!(
        switch(&mut harness, bob, Some(account))?,
        [
            vec![K::ChannelPolicyChanged],
            vec![
                K::SessionVisible,
                K::AccountLabelChanged,
                K::AccountStateChanged,
                K::InviteRemoved,
                K::ChannelHidden
            ],
            vec![K::ChannelPolicyChanged]
        ]
    );
    assert_eq!(say(&mut harness, carol)?, heard(&[EDGE_A, EDGE_C]));
    assert_replicas_match_the_cut(&harness)?;
    Ok(())
}

#[test]
fn an_account_logging_out_hides_its_invite_copy_on_that_edge() -> Result<(), DomainError> {
    let mut harness = three_edges()?;
    let alice = harness.open(1, EDGE_A)?;
    let bob = harness.open(2, EDGE_B)?;
    harness.register(bob, 41)?;
    join(&mut harness, alice)?;
    invite_user(&mut harness, alice, 2)?;
    assert_eq!(
        switch(&mut harness, bob, None)?,
        [
            Vec::new(),
            vec![K::SessionVisible, K::InviteRemoved, K::ChannelHidden],
            Vec::new()
        ]
    );
    assert_eq!(say(&mut harness, alice)?, heard(&[EDGE_A]));
    assert_replicas_match_the_cut(&harness)?;
    Ok(())
}

/// A MODE command that leaves every mode as it was persists nothing and
/// projects nothing, so the channel revision every edge holds must stay the
/// revision the next channel message binds to.
#[test]
fn a_mode_command_without_an_effective_change_keeps_the_channel_revision_edges_hold()
-> Result<(), DomainError> {
    let mut harness = three_edges()?;
    let alice = harness.open(1, EDGE_A)?;
    let bob = harness.open(2, EDGE_B)?;
    join(&mut harness, alice)?;
    join(&mut harness, bob)?;
    let name = room()?;
    let channel = harness
        .state
        .resolve_channel(&name)
        .ok_or(DomainError::NotFound)?;
    let before = harness
        .state
        .durable_channel(channel)
        .ok_or(DomainError::NotFound)?
        .revision;
    let unchanged =
        || CanonicalCommand::mode(name.clone(), vec![crate::ModeChange::TopicProtected(true)]);
    let plan = harness.plan(alice, unchanged)?;
    assert!(plan.durable_writes().is_empty());
    assert_eq!(
        deliver(&mut harness, plan)?,
        [Vec::new(), Vec::new(), Vec::new()]
    );
    let after = harness
        .state
        .durable_channel(channel)
        .ok_or(DomainError::NotFound)?
        .revision;
    assert_eq!(
        after, before,
        "an unpersisted change must not advance the channel"
    );
    assert_replicas_match_the_cut(&harness)?;
    assert_eq!(say(&mut harness, alice)?, heard(&[EDGE_A, EDGE_B]));
    Ok(())
}

#[test]
fn a_login_names_its_public_label_to_the_home_and_member_edges_and_a_logout_does_not()
-> Result<(), DomainError> {
    let mut harness = three_edges()?;
    let alice = harness.open(1, EDGE_A)?;
    let bob = harness.open(2, EDGE_B)?;
    // Alice and bob share the room; carol, alone on edge C, shares nothing.
    let _carol = harness.open(3, EDGE_C)?;
    join(&mut harness, alice)?;
    join(&mut harness, bob)?;
    let account_id =
        AccountId::from_random(agenc_relay_types::AccountRandomId::from_bytes([43; 16]));
    let mut account =
        crate::AccountState::new(account_id, Generation::new(1)?, harness.state.revision());
    account.label = Some(crate::AccountLabelValue::parse("Kestrel")?);
    let plan = harness.state.plan_account_created(account)?;
    harness.commit(plan, &MutationContext::default())?;

    let session = harness.state.session(bob).ok_or(DomainError::NotFound)?;
    let plan = harness.state.plan_session_account_switch(
        bob,
        session.generation(),
        Some((account_id, Generation::new(1)?)),
    )?;
    let (projection, revision) = harness.advance(plan, &MutationContext::default())?;
    assert_eq!(replicate(&mut harness, &projection, revision)?, ACCEPTED);
    for (edge, home) in [(EDGE_A, false), (EDGE_B, true)] {
        let named: Vec<_> = events_for(&projection, edge)
            .into_iter()
            .filter_map(|event| match event {
                ProjectedEvent::AccountLabelChanged(view) => Some(view),
                _ => None,
            })
            .collect();
        let [view] = named.as_slice() else {
            return Err(DomainError::InvariantViolation);
        };
        assert_eq!(view.source.user_id, bob);
        assert_eq!(
            view.source
                .account_label
                .as_ref()
                .map(|label| label.as_str()),
            Some("Kestrel")
        );
        // Only the home edge receives the session's own projection.
        assert_eq!(view.home_projection.is_some(), home);
    }
    assert!(
        events_for(&projection, EDGE_C)
            .iter()
            .all(|event| event.kind() != K::AccountLabelChanged)
    );

    let session = harness.state.session(bob).ok_or(DomainError::NotFound)?;
    let plan = harness
        .state
        .plan_session_account_switch(bob, session.generation(), None)?;
    let logout = deliver(&mut harness, plan)?;
    assert!(
        logout
            .iter()
            .flatten()
            .all(|kind| *kind != K::AccountLabelChanged),
        "{logout:?}"
    );
    assert_replicas_match_the_cut(&harness)?;
    Ok(())
}
