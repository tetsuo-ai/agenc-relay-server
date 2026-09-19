//! Projection paths reached only by QUIT, MONITOR, a role change on a
//! registered channel, invites held by several principals, and a mode
//! command that changes nothing.
#![forbid(unsafe_code)]

use super::*;
use crate::{ChannelCommand, ModeChange, ModeOperation, PresenceCommand, Role};
use agenc_ircd_types::FederationEventKind as K;

fn room() -> Result<ChannelNameValue, DomainError> {
    ChannelNameValue::parse("#room")
}

fn join(harness: &mut Harness, user: UserId) -> Result<MutationProjection, DomainError> {
    let name = room()?;
    let join = || CanonicalCommand::join(vec![ChannelTarget::new(name.clone(), false)]);
    harness.run(user, join, &MutationContext::default())
}

fn channel_of(harness: &Harness) -> Result<ChannelInstanceId, DomainError> {
    harness
        .state
        .resolve_channel(&room()?)
        .ok_or(DomainError::NotFound)
}

fn invite(harness: &mut Harness, inviter: UserId, target: u8) -> Result<(), DomainError> {
    let name = room()?;
    let nickname = NicknameValue::parse(&format!("user{target}"))?;
    let build = || Ok(CanonicalCommand::invite(nickname.clone(), name.clone()));
    harness.run(inviter, build, &MutationContext::default())?;
    Ok(())
}

fn holds_invite(harness: &Harness, edge: ServerId, channel: ChannelInstanceId) -> bool {
    harness.index.edge(edge).is_some_and(|standing| {
        standing
            .keys()
            .any(|key| key.kind() == ProjectionKey::INVITE)
            && standing.holds_channel(channel)
    })
}

fn nickname_of(harness: &Harness, user: UserId) -> Result<NicknameValue, DomainError> {
    Ok(harness
        .state
        .session(user)
        .ok_or(DomainError::NotFound)?
        .nickname()
        .clone())
}

#[test]
fn mode_bits_omit_the_topic_bit_when_topics_are_unprotected() {
    let modes = crate::ChannelModes {
        invite_only: false,
        moderated: true,
        topic_protected: false,
        join_key: false,
    };
    assert_eq!(
        simple_mode_bits(modes, crate::Visibility::Listed),
        0b00_0110
    );
    assert_eq!(
        simple_mode_bits(modes, crate::Visibility::Unlisted),
        0b00_1110
    );
    assert_eq!(
        simple_mode_bits(modes, crate::Visibility::Secret),
        0b01_0110
    );
}

/// A QUIT plan lists the channel departures before the session hide, and
/// the projection folds those departures into one hide carrying the
/// client's own reason.
#[test]
fn a_client_quit_carries_its_reason_and_folds_its_parts_into_the_hide() -> Result<(), DomainError> {
    let mut harness = Harness::new()?;
    let alice = harness.open(1, EDGE_A)?;
    let bob = harness.open(2, EDGE_B)?;
    join(&mut harness, alice)?;
    join(&mut harness, bob)?;
    let channel = channel_of(&harness)?;
    let quit = || {
        Ok(CanonicalCommand::quit(Some(DepartureReason::try_from_str(
            "gone fishing",
            ControlPolicy::RejectAll,
        )?)))
    };
    let context = MutationContext {
        reason: "gone fishing".to_owned(),
        hide_kind: Some(SessionHideKind::ClientQuit),
        ..MutationContext::default()
    };
    let projection = harness.run(bob, quit, &context)?;
    assert_eq!(
        kinds(&events_for(&projection, EDGE_B)),
        vec![K::SessionHidden, K::ChannelHidden]
    );
    assert_eq!(
        kinds(&events_for(&projection, EDGE_A)),
        vec![K::SessionHidden]
    );
    for edge in [EDGE_A, EDGE_B] {
        let Some(ProjectedEvent::SessionHidden {
            source,
            channels,
            kind,
            reason,
            ..
        }) = events_for(&projection, edge).first().copied()
        else {
            return Err(DomainError::InvariantViolation);
        };
        assert_eq!(source.user_id, bob);
        assert_eq!(*kind, SessionHideKind::ClientQuit);
        assert_eq!(reason, "gone fishing");
        let listed: Vec<ChannelInstanceId> = channels.iter().map(|(listed, _)| *listed).collect();
        assert_eq!(listed, vec![channel]);
    }
    assert!(harness.state.session(bob).is_none());
    Ok(())
}

/// A session opening is shown to every edge with a session monitoring its
/// nickname, and the home edge sees it exactly once even when it monitors.
#[test]
fn a_session_opening_reaches_monitoring_edges_and_its_home_once() -> Result<(), DomainError> {
    let mut harness = Harness::new()?;
    let alice = harness.open(1, EDGE_A)?;
    let carol = harness.open(3, EDGE_B)?;
    let watched = NicknameValue::parse("user2")?;
    for watcher in [alice, carol] {
        let monitor =
            || CanonicalCommand::presence(PresenceCommand::MonitorAdd(vec![watched.clone()]));
        let projection = harness.run(watcher, monitor, &MutationContext::default())?;
        assert_eq!(projection.event_count(), 0);
    }
    let seed = harness.seed(2, EDGE_B)?;
    let bob = seed.user_id;
    let plan = harness.state.plan_session_opened(seed)?;
    let projection = harness.commit(plan, &MutationContext::default())?;
    for edge in [EDGE_A, EDGE_B] {
        let events = events_for(&projection, edge);
        assert_eq!(kinds(&events), vec![K::SessionVisible]);
        let Some(ProjectedEvent::SessionVisible(view)) = events.first().copied() else {
            return Err(DomainError::InvariantViolation);
        };
        assert_eq!(view.source.user_id, bob);
        assert_eq!(view.home_projection.is_some(), edge == EDGE_B);
    }
    assert_eq!(projection.event_count(), 2);
    Ok(())
}

/// A role change on a registered channel is an account grant, not a session
/// prefix, so every member edge observes the recomputed memberships of the
/// target's account and no prefix delta.
#[test]
fn a_role_change_on_a_registered_channel_recomputes_the_target_account_memberships()
-> Result<(), DomainError> {
    let mut harness = Harness::new()?;
    let alice = harness.open(1, EDGE_A)?;
    let bob = harness.open(2, EDGE_B)?;
    harness.register(alice, 41)?;
    harness.register(bob, 42)?;
    join(&mut harness, alice)?;
    join(&mut harness, bob)?;
    let channel = channel_of(&harness)?;
    let register = || Ok(CanonicalCommand::channel(ChannelCommand::Register(channel)));
    harness.run(alice, register, &MutationContext::default())?;
    let name = room()?;
    let target = nickname_of(&harness, bob)?;
    let build = || {
        CanonicalCommand::mode(
            name.clone(),
            vec![ModeChange::Role {
                operation: ModeOperation::Add,
                target: target.clone(),
                role: Role::Voice,
            }],
        )
    };
    let context = MutationContext {
        actor: Some(alice),
        ..MutationContext::default()
    };
    let projection = harness.run(alice, build, &context)?;
    for edge in [EDGE_A, EDGE_B] {
        let events = events_for(&projection, edge);
        assert_eq!(kinds(&events), vec![K::ChannelMembershipsRecomputed]);
        let Some(ProjectedEvent::ChannelMembershipsRecomputed {
            channel_id,
            actor,
            memberships,
            ..
        }) = events.first().copied()
        else {
            return Err(DomainError::InvariantViolation);
        };
        assert_eq!(*channel_id, channel);
        assert_eq!(actor.0.as_ref().map(|view| view.user_id), Some(alice));
        let Some(recomputed) = memberships.first() else {
            return Err(DomainError::InvariantViolation);
        };
        assert_eq!(memberships.len(), 1);
        assert_eq!(recomputed.membership.user_id, bob);
        assert_eq!(recomputed.membership.role, Role::Voice);
    }
    Ok(())
}

/// Two guests on different edges hold invites to the same channel; when one
/// leaves, only the edge that hosted it loses an invite copy.
#[test]
fn hiding_one_invited_guest_leaves_the_other_principals_invite_in_place() -> Result<(), DomainError>
{
    let mut harness = Harness::new()?;
    let alice = harness.open(1, EDGE_A)?;
    let _bob = harness.open(2, EDGE_A)?;
    let carol = harness.open(3, EDGE_B)?;
    join(&mut harness, alice)?;
    let channel = channel_of(&harness)?;
    invite(&mut harness, alice, 2)?;
    invite(&mut harness, alice, 3)?;
    assert!(holds_invite(&harness, EDGE_A, channel));
    assert!(holds_invite(&harness, EDGE_B, channel));
    let plan = harness.state.plan_session_disconnected(carol)?;
    let projection = harness.commit(plan, &MutationContext::default())?;
    assert_eq!(
        kinds(&events_for(&projection, EDGE_B)),
        vec![K::SessionHidden, K::InviteRemoved, K::ChannelHidden]
    );
    assert_eq!(
        kinds(&events_for(&projection, EDGE_A)),
        vec![K::ChannelPolicyChanged]
    );
    assert!(!holds_invite(&harness, EDGE_B, channel));
    assert!(holds_invite(&harness, EDGE_A, channel));
    Ok(())
}

/// A mode command that leaves every mode as it was projects no event; the
/// member edges only re-receive their unchanged standing records.
#[test]
fn a_mode_command_without_an_effective_change_projects_nothing() -> Result<(), DomainError> {
    let mut harness = Harness::new()?;
    let alice = harness.open(1, EDGE_A)?;
    let bob = harness.open(2, EDGE_B)?;
    join(&mut harness, alice)?;
    join(&mut harness, bob)?;
    let name = room()?;
    let build = || CanonicalCommand::mode(name.clone(), vec![ModeChange::TopicProtected(true)]);
    let context = MutationContext {
        actor: Some(alice),
        ..MutationContext::default()
    };
    let projection = harness.run(alice, build, &context)?;
    assert_eq!(projection.event_count(), 0);
    assert!(
        projection
            .edges
            .iter()
            .all(|delta| delta.removals.is_empty())
    );
    Ok(())
}
