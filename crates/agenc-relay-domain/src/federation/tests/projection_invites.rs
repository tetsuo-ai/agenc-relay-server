//! Invite copies follow the edges hosting their target principal, and a
//! derivation refuses a plan prepared against another revision.
#![forbid(unsafe_code)]

use super::*;
use crate::Principal;
use crate::federation::record::InviteRemovalKind;
use agenc_relay_types::{AccountId, FederationEventKind as K};

const EDGE_C: ServerId = ServerId::from_bytes([12; 16]);
const EDGES: [ServerId; 3] = [EDGE_A, EDGE_B, EDGE_C];

fn room() -> Result<ChannelNameValue, DomainError> {
    ChannelNameValue::parse("#room")
}

fn join(harness: &mut Harness, user: UserId) -> Result<MutationProjection, DomainError> {
    let name = room()?;
    let join = || CanonicalCommand::join(vec![ChannelTarget::new(name.clone(), false)]);
    harness.run(user, join, &MutationContext::default())
}

fn invite(
    harness: &mut Harness,
    inviter: UserId,
    target: u8,
) -> Result<MutationProjection, DomainError> {
    let name = room()?;
    let nickname = NicknameValue::parse(&format!("user{target}"))?;
    let build = || Ok(CanonicalCommand::invite(nickname.clone(), name.clone()));
    harness.run(inviter, build, &MutationContext::default())
}

fn adopt(
    harness: &mut Harness,
    user: UserId,
    account: AccountId,
) -> Result<MutationProjection, DomainError> {
    let session = harness.state.session(user).ok_or(DomainError::NotFound)?;
    let plan = harness.state.plan_session_account_switch(
        user,
        session.generation(),
        Some((account, Generation::new(1)?)),
    )?;
    harness.commit(plan, &MutationContext::default())
}

fn disconnect(harness: &mut Harness, user: UserId) -> Result<MutationProjection, DomainError> {
    let plan = harness.state.plan_session_disconnected(user)?;
    harness.commit(plan, &MutationContext::default())
}

fn kinds_per_edge(projection: &MutationProjection) -> [Vec<K>; 3] {
    EDGES.map(|edge| kinds(&events_for(projection, edge)))
}

/// `alice` on edge A owns `#room`; the invited account is held by `bob` on
/// edge A and `carol` on edge B, so both edges host the invite target.
struct Invited {
    harness: Harness,
    alice: UserId,
    bob: UserId,
    carol: UserId,
    account: AccountId,
    channel: ChannelInstanceId,
    projection: MutationProjection,
}

fn invited() -> Result<Invited, DomainError> {
    let mut harness = Harness::new()?;
    harness.replicas.insert(EDGE_C, EdgeReplica::new(EDGE_C));
    let alice = harness.open(1, EDGE_A)?;
    let bob = harness.open(2, EDGE_A)?;
    let carol = harness.open(3, EDGE_B)?;
    let account = harness.register(bob, 41)?;
    adopt(&mut harness, carol, account)?;
    join(&mut harness, alice)?;
    let projection = invite(&mut harness, alice, 2)?;
    let channel = harness
        .state
        .resolve_channel(&room()?)
        .ok_or(DomainError::NotFound)?;
    Ok(Invited {
        harness,
        alice,
        bob,
        carol,
        account,
        channel,
        projection,
    })
}

fn holds_invite(harness: &Harness, edge: ServerId, channel: ChannelInstanceId) -> bool {
    harness.index.edge(edge).is_some_and(|standing| {
        standing
            .keys()
            .any(|key| key.kind() == ProjectionKey::INVITE)
            && standing.holds_channel(channel)
    })
}

#[test]
fn an_account_invite_reaches_every_edge_hosting_the_account() -> Result<(), DomainError> {
    let fixture = invited()?;
    assert_eq!(
        kinds_per_edge(&fixture.projection),
        [
            vec![K::Invited],
            vec![K::ChannelVisible, K::Invited],
            Vec::new()
        ]
    );
    for edge in [EDGE_A, EDGE_B] {
        let events = events_for(&fixture.projection, edge);
        let Some(ProjectedEvent::Invited {
            local_projection: Some(record),
            inviter,
            named_target,
            ..
        }) = events.last().copied()
        else {
            return Err(DomainError::InvariantViolation);
        };
        assert_eq!(record.target, Principal::Account(fixture.account));
        assert_eq!(record.inviter_user_id, fixture.alice);
        assert_eq!(inviter.user_id, fixture.alice);
        assert_eq!(named_target.user_id, fixture.bob);
        assert!(holds_invite(&fixture.harness, edge, fixture.channel));
    }
    assert!(!holds_invite(&fixture.harness, EDGE_C, fixture.channel));
    Ok(())
}

#[test]
fn adopting_an_invited_account_on_a_new_edge_reprojects_the_invite() -> Result<(), DomainError> {
    let mut fixture = invited()?;
    let dave = fixture.harness.open(4, EDGE_C)?;
    let projection = adopt(&mut fixture.harness, dave, fixture.account)?;
    assert_eq!(
        kinds_per_edge(&projection),
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
    let events = events_for(&projection, EDGE_C);
    let Some(ProjectedEvent::Invited {
        local_projection: Some(record),
        ..
    }) = events.last().copied()
    else {
        return Err(DomainError::InvariantViolation);
    };
    assert_eq!(record.target, Principal::Account(fixture.account));
    assert!(holds_invite(&fixture.harness, EDGE_C, fixture.channel));
    Ok(())
}

#[test]
fn a_second_session_of_the_account_on_a_holding_edge_gets_no_second_copy() -> Result<(), DomainError>
{
    let mut fixture = invited()?;
    let dave = fixture.harness.open(4, EDGE_C)?;
    adopt(&mut fixture.harness, dave, fixture.account)?;
    let erin = fixture.harness.open(5, EDGE_C)?;
    let projection = adopt(&mut fixture.harness, erin, fixture.account)?;
    assert_eq!(
        kinds_per_edge(&projection),
        [
            Vec::new(),
            Vec::new(),
            vec![K::SessionVisible, K::AccountLabelChanged]
        ]
    );
    Ok(())
}

#[test]
fn the_last_account_session_leaving_an_edge_hides_its_invite_copy() -> Result<(), DomainError> {
    let mut fixture = invited()?;
    let projection = disconnect(&mut fixture.harness, fixture.carol)?;
    assert_eq!(
        kinds_per_edge(&projection),
        [
            Vec::new(),
            vec![K::SessionHidden, K::InviteRemoved, K::ChannelHidden],
            Vec::new()
        ]
    );
    let events = events_for(&projection, EDGE_B);
    let Some(ProjectedEvent::InviteRemoved {
        channel_id, kind, ..
    }) = events.get(1).copied()
    else {
        return Err(DomainError::InvariantViolation);
    };
    assert_eq!(*channel_id, fixture.channel);
    assert_eq!(*kind, InviteRemovalKind::ProjectionHidden);
    assert!(!holds_invite(&fixture.harness, EDGE_B, fixture.channel));
    assert!(holds_invite(&fixture.harness, EDGE_A, fixture.channel));
    Ok(())
}

#[test]
fn an_account_session_leaving_an_edge_that_still_hosts_the_account_keeps_the_copy()
-> Result<(), DomainError> {
    let mut fixture = invited()?;
    let dave = fixture.harness.open(4, EDGE_B)?;
    adopt(&mut fixture.harness, dave, fixture.account)?;
    let projection = disconnect(&mut fixture.harness, fixture.carol)?;
    assert_eq!(
        kinds_per_edge(&projection),
        [Vec::new(), vec![K::SessionHidden], Vec::new()]
    );
    assert!(holds_invite(&fixture.harness, EDGE_B, fixture.channel));
    Ok(())
}

#[test]
fn joining_consumes_the_invite_on_every_holding_edge() -> Result<(), DomainError> {
    let mut fixture = invited()?;
    let projection = join(&mut fixture.harness, fixture.bob)?;
    assert_eq!(
        kinds_per_edge(&projection),
        [
            vec![K::MemberJoined, K::InviteRemoved],
            vec![K::InviteRemoved, K::ChannelHidden],
            Vec::new()
        ]
    );
    for edge in [EDGE_A, EDGE_B] {
        let events = events_for(&projection, edge);
        let consumed = events.iter().any(|event| {
            matches!(
                event,
                ProjectedEvent::InviteRemoved {
                    kind: InviteRemovalKind::Consumed,
                    ..
                }
            )
        });
        assert!(consumed, "the join consumes the copy on every holder");
    }
    assert!(!holds_invite(&fixture.harness, EDGE_B, fixture.channel));
    Ok(())
}

#[test]
fn destroying_the_channel_reaches_the_edge_entitled_only_by_an_invite() -> Result<(), DomainError> {
    let mut fixture = invited()?;
    let projection = disconnect(&mut fixture.harness, fixture.alice)?;
    assert_eq!(
        kinds_per_edge(&projection),
        [
            vec![K::SessionHidden, K::ChannelDestroyed],
            vec![K::ChannelDestroyed],
            Vec::new()
        ]
    );
    for edge in [EDGE_A, EDGE_B] {
        let standing = fixture
            .harness
            .index
            .edge(edge)
            .ok_or(DomainError::NotFound)?;
        assert!(!standing.holds_channel(fixture.channel));
        assert!(
            !standing
                .keys()
                .any(|key| key.kind() == ProjectionKey::INVITE)
        );
    }
    Ok(())
}

#[test]
fn the_snapshot_cut_of_an_invite_only_edge_is_the_channel_the_invite_and_its_sessions()
-> Result<(), DomainError> {
    let fixture = invited()?;
    let cut = CoordinatorProjection::standing_of(&fixture.harness.state, EDGE_B);
    let cut_kinds: Vec<u16> = cut.iter().map(|record| record.key().kind()).collect();
    assert_eq!(
        cut_kinds,
        vec![
            ProjectionKey::SESSION,
            ProjectionKey::CHANNEL_DETAIL,
            ProjectionKey::INVITE,
            ProjectionKey::ACCOUNT
        ]
    );
    assert!(CoordinatorProjection::standing_of(&fixture.harness.state, EDGE_C).is_empty());
    Ok(())
}

#[test]
fn derive_refuses_a_plan_prepared_against_an_older_revision() -> Result<(), DomainError> {
    let mut harness = Harness::new()?;
    let stale = harness
        .state
        .plan_session_opened(harness.seed(1, EDGE_A)?)?;
    harness.open(2, EDGE_B)?;
    let derived = harness
        .index
        .derive(&harness.state, &stale, &MutationContext::default());
    assert_eq!(derived.err(), Some(DomainError::StaleRevision));
    Ok(())
}

#[test]
fn install_edge_replaces_the_standing_of_one_edge_only() -> Result<(), DomainError> {
    let mut fixture = invited()?;
    let before_a = fixture
        .harness
        .index
        .edge(EDGE_A)
        .ok_or(DomainError::NotFound)?
        .entry_count();
    fixture.harness.index.install_edge(EDGE_B, &[]);
    let standing_b = fixture
        .harness
        .index
        .edge(EDGE_B)
        .ok_or(DomainError::NotFound)?;
    assert_eq!(standing_b.entry_count(), 0);
    let standing_a = fixture
        .harness
        .index
        .edge(EDGE_A)
        .ok_or(DomainError::NotFound)?;
    assert_eq!(standing_a.entry_count(), before_a);
    let cut = CoordinatorProjection::standing_of(&fixture.harness.state, EDGE_B);
    fixture.harness.index.install_edge(EDGE_B, &cut);
    assert!(holds_invite(&fixture.harness, EDGE_B, fixture.channel));
    Ok(())
}
