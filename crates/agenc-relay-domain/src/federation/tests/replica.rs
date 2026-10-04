#![forbid(unsafe_code)]

//! Edge replica invariants: snapshot install, revision rules, locality, and
//! unreferenced-account cleanup.

use std::error::Error;

use agenc_relay_types::{
    AccountId, AccountRandomId, ChannelInstanceId, Generation, InviteId, Revision, ServerId,
    SessionId, UserId, UtcSecond,
};

use super::*;
use crate::federation::record::{
    AccountRecord, ChannelDetailRecord, InviteRecord, MembershipRecord, MembershipView,
    ProjectionRecord, SessionEventView, SessionHideKind, SessionRecord, SourceView,
};
use crate::model::test_public_cloak;
use crate::{ChannelNameValue, DisplayNameValue, DomainError, NicknameValue, Role};

type TestResult = Result<(), Box<dyn Error>>;

const LOCAL: ServerId = ServerId::from_bytes([10; 16]);
const REMOTE: ServerId = ServerId::from_bytes([11; 16]);

#[path = "replica/durable_changes.rs"]
mod durable_changes;

#[path = "replica/reference_fences.rs"]
mod reference_fences;

fn revision(value: u64) -> Revision {
    Revision::new(value).unwrap_or_else(|_| revision(0))
}

fn account_id() -> AccountId {
    AccountId::from_random(AccountRandomId::from_bytes([5; 16]))
}

fn session(
    n: u8,
    home: ServerId,
    account: Option<(AccountId, Generation)>,
) -> Result<SessionRecord, DomainError> {
    Ok(SessionRecord {
        session_id: SessionId::from_bytes([n; 16]),
        user_id: UserId::from_bytes([n; 16]),
        home_server_id: home,
        session_revision: revision(1),
        account,
        nickname: NicknameValue::parse(&format!("user{n}"))?,
        display_name: DisplayNameValue::prepare("User")?,
        public_cloak: test_public_cloak(n)?,
        account_label: None,
        user_mode_bits: 1,
        away: None,
    })
}

fn detail(n: u8, rev: u64) -> Result<ChannelDetailRecord, DomainError> {
    Ok(ChannelDetailRecord {
        channel_id: ChannelInstanceId::from_bytes([n; 16]),
        name: ChannelNameValue::parse(&format!("#c{n}"))?,
        channel_revision: revision(rev),
        visibility: crate::Visibility::Listed,
        content_policy: crate::ContentPolicy::Plaintext,
        persistence: crate::PersistencePolicy::Ephemeral,
        simple_mode_bits: 4,
        history: crate::HistoryPolicy::Off,
        e2ee_route_binding: None,
    })
}

fn membership(channel: u8, user: u8, rev: u64) -> MembershipRecord {
    MembershipRecord {
        channel_id: ChannelInstanceId::from_bytes([channel; 16]),
        user_id: UserId::from_bytes([user; 16]),
        role: Role::Member,
        membership_revision: revision(rev),
        joined_at: UtcSecond::from_unix_seconds(1),
    }
}

fn view(record: &SessionRecord, home: bool) -> SessionEventView {
    SessionEventView {
        source: record.source_view(),
        home_projection: home.then(|| record.clone()),
    }
}

fn source(record: &SessionRecord) -> SourceView {
    record.source_view()
}

#[test]
fn snapshot_install_validates_order_references_and_locality() -> TestResult {
    let mut replica = EdgeReplica::new(LOCAL);
    let alice = session(1, LOCAL, None)?;
    let entries = vec![
        ProjectionRecord::Session(alice.clone()),
        ProjectionRecord::ChannelDetail(detail(2, 3)?),
        ProjectionRecord::Membership(membership(2, 1, 3)),
    ];
    replica.install(7, entries.clone())?;
    assert_eq!(replica.projection_generation(), 7);
    assert_eq!(replica.entry_count(), 3);
    assert!(
        replica
            .membership(ChannelInstanceId::from_bytes([2; 16]), alice.user_id)
            .is_some()
    );

    let mut reordered = entries.clone();
    reordered.swap(0, 1);
    assert_eq!(
        replica.install(8, reordered),
        Err(ReplicaError::SnapshotOrder)
    );
    assert_eq!(replica.projection_generation(), 7);

    let dangling = vec![ProjectionRecord::Membership(membership(2, 1, 3))];
    assert_eq!(
        replica.install(8, dangling),
        Err(ReplicaError::DanglingReference)
    );
    let orphan_detail = vec![ProjectionRecord::ChannelDetail(detail(2, 3)?)];
    assert_eq!(
        replica.install(8, orphan_detail),
        Err(ReplicaError::DanglingReference)
    );
    let remote = vec![ProjectionRecord::Session(session(1, REMOTE, None)?)];
    assert_eq!(replica.install(8, remote), Err(ReplicaError::WrongHome));
    let unreferenced_account = vec![ProjectionRecord::Account(AccountRecord {
        account_id: account_id(),
        account_session_generation: Generation::new(1)?,
        account_revision: revision(1),
    })];
    assert_eq!(
        replica.install(8, unreferenced_account),
        Err(ReplicaError::DanglingReference)
    );
    let zero_account = vec![ProjectionRecord::Account(AccountRecord {
        account_id: account_id(),
        account_session_generation: Generation::new(0)?,
        account_revision: revision(1),
    })];
    assert_eq!(
        replica.install(8, zero_account),
        Err(ReplicaError::InvalidRecord)
    );
    let mut bad_bits = session(1, LOCAL, None)?;
    bad_bits.user_mode_bits = 2;
    assert_eq!(
        replica.install(8, vec![ProjectionRecord::Session(bad_bits)]),
        Err(ReplicaError::InvalidRecord)
    );
    let mut bad_detail = detail(2, 3)?;
    bad_detail.simple_mode_bits = 0b11_1100;
    assert_eq!(
        replica.install(8, vec![ProjectionRecord::ChannelDetail(bad_detail)]),
        Err(ReplicaError::InvalidRecord)
    );
    let account = Some((account_id(), Generation::new(2)?));
    let authenticated = session(1, LOCAL, account)?;
    let mismatched = vec![
        ProjectionRecord::Session(authenticated.clone()),
        ProjectionRecord::Account(AccountRecord {
            account_id: account_id(),
            account_session_generation: Generation::new(1)?,
            account_revision: revision(1),
        }),
    ];
    assert_eq!(
        replica.install(8, mismatched),
        Err(ReplicaError::InvalidRecord)
    );
    let consistent = vec![
        ProjectionRecord::Session(authenticated),
        ProjectionRecord::Account(AccountRecord {
            account_id: account_id(),
            account_session_generation: Generation::new(2)?,
            account_revision: revision(1),
        }),
    ];
    replica.install(9, consistent)?;
    assert!(replica.account(account_id()).is_some());
    Ok(())
}

#[test]
fn event_application_enforces_revision_and_home_rules() -> TestResult {
    let mut replica = EdgeReplica::new(LOCAL);
    let alice = session(1, LOCAL, None)?;
    let bob = session(2, REMOTE, None)?;
    let channel = ChannelInstanceId::from_bytes([2; 16]);

    let outcome = replica.apply(&ProjectedEvent::SessionVisible(view(&alice, true)), 1)?;
    assert!(outcome.local_recipients.contains(&alice.user_id));
    assert_eq!(
        replica.apply(&ProjectedEvent::SessionVisible(view(&bob, true)), 1),
        Err(ReplicaError::WrongHome)
    );
    assert_eq!(
        replica.apply(&ProjectedEvent::SessionVisible(view(&alice, false)), 1),
        Err(ReplicaError::HomeSessionRevision)
    );
    replica.apply(&ProjectedEvent::SessionVisible(view(&bob, false)), 1)?;

    let mut regressed = alice.clone();
    regressed.session_revision = revision(0);
    replica.apply(&ProjectedEvent::SessionVisible(view(&alice, true)), 1)?;
    replica.apply(&ProjectedEvent::UserModesChanged(alice.clone()), 1)?;
    let mut newer = alice.clone();
    newer.session_revision = revision(5);
    replica.apply(&ProjectedEvent::UserModesChanged(newer), 5)?;
    assert_eq!(
        replica.apply(&ProjectedEvent::UserModesChanged(regressed), 6),
        Err(ReplicaError::Revision)
    );

    replica.apply(&ProjectedEvent::ChannelVisible(detail(2, 6)?), 6)?;
    assert_eq!(
        replica.apply(&ProjectedEvent::ChannelVisible(detail(2, 6)?), 6),
        Err(ReplicaError::UnknownEntity)
    );
    let joined = ProjectedEvent::MemberJoined {
        view: MembershipView {
            membership: membership(2, 1, 6),
            source: source(&alice),
        },
        home_session_revision: Some(revision(6)),
        display_name: DisplayNameValue::prepare("User")?,
    };
    replica.apply(&joined, 6)?;
    assert_eq!(replica.apply(&joined, 6), Err(ReplicaError::UnknownEntity));
    let remote_join = ProjectedEvent::MemberJoined {
        view: MembershipView {
            membership: membership(2, 2, 6),
            source: source(&bob),
        },
        home_session_revision: None,
        display_name: DisplayNameValue::prepare("User")?,
    };
    let outcome = replica.apply(&remote_join, 6)?;
    assert!(outcome.local_recipients.contains(&alice.user_id));
    assert!(replica.membership(channel, bob.user_id).is_none());
    let wrong_home = ProjectedEvent::MemberJoined {
        view: MembershipView {
            membership: membership(2, 2, 6),
            source: source(&bob),
        },
        home_session_revision: Some(revision(6)),
        display_name: DisplayNameValue::prepare("User")?,
    };
    assert_eq!(
        replica.apply(&wrong_home, 6),
        Err(ReplicaError::HomeSessionRevision)
    );

    let stale_part = ProjectedEvent::MemberParted {
        channel_id: channel,
        source: source(&bob),
        resulting_revision: revision(5),
        home_session_revision: None,
        reason: String::new(),
    };
    assert_eq!(replica.apply(&stale_part, 7), Err(ReplicaError::Revision));
    let jumped = ProjectedEvent::MemberParted {
        channel_id: channel,
        source: source(&bob),
        resulting_revision: revision(8),
        home_session_revision: None,
        reason: String::new(),
    };
    assert_eq!(replica.apply(&jumped, 7), Err(ReplicaError::Revision));
    let part = ProjectedEvent::MemberParted {
        channel_id: channel,
        source: source(&bob),
        resulting_revision: revision(7),
        home_session_revision: None,
        reason: String::new(),
    };
    replica.apply(&part, 7)?;
    assert_eq!(
        replica
            .channel(channel)
            .map(|detail| detail.channel_revision),
        Some(revision(7))
    );

    let hidden_with_children = ProjectedEvent::ChannelHidden {
        channel_id: channel,
        last_revision: revision(7),
    };
    assert_eq!(
        replica.apply(&hidden_with_children, 8),
        Err(ReplicaError::ChildrenRemain)
    );
    let kicked = ProjectedEvent::Kicked {
        channel_id: channel,
        actor: crate::federation::record::ActorView(None),
        target: source(&alice),
        resulting_revision: revision(8),
        target_home_session_revision: Some(revision(8)),
        reason: "out".to_owned(),
    };
    let outcome = replica.apply(&kicked, 8)?;
    assert_eq!(
        outcome.removed,
        vec![ProjectionKey::membership(channel, alice.user_id)]
    );
    let hidden = ProjectedEvent::ChannelHidden {
        channel_id: channel,
        last_revision: revision(8),
    };
    replica.apply(&hidden, 8)?;
    assert!(replica.channel(channel).is_none());
    assert_eq!(replica.apply(&hidden, 9), Err(ReplicaError::UnknownEntity));
    replica.validate()?;
    Ok(())
}

#[test]
fn session_hidden_and_invites_erase_dependent_state() -> TestResult {
    let mut replica = EdgeReplica::new(LOCAL);
    let account = Some((account_id(), Generation::new(2)?));
    let alice = session(1, LOCAL, account)?;
    let record = AccountRecord {
        account_id: account_id(),
        account_session_generation: Generation::new(2)?,
        account_revision: revision(1),
    };
    assert_eq!(
        replica.apply(&ProjectedEvent::AccountStateChanged(record), 1),
        Err(ReplicaError::DanglingReference)
    );
    replica.apply(&ProjectedEvent::SessionVisible(view(&alice, true)), 1)?;
    assert_eq!(replica.validate(), Err(ReplicaError::DanglingReference));
    replica.apply(&ProjectedEvent::AccountStateChanged(record), 1)?;
    replica.validate()?;
    let mut wrong_generation = alice.clone();
    wrong_generation.account = Some((account_id(), Generation::new(3)?));
    assert_eq!(
        replica.apply(
            &ProjectedEvent::SessionVisible(view(&wrong_generation, true)),
            1
        ),
        Err(ReplicaError::InvalidRecord)
    );
    replica.apply(&ProjectedEvent::SessionVisible(view(&alice, true)), 1)?;
    let older = AccountRecord {
        account_revision: revision(0),
        ..record
    };
    assert_eq!(
        replica.apply(&ProjectedEvent::AccountStateChanged(older), 2),
        Err(ReplicaError::Revision)
    );

    let channel = ChannelInstanceId::from_bytes([2; 16]);
    let invite_id = InviteId::from_bytes([3; 16]);
    replica.apply(&ProjectedEvent::ChannelVisible(detail(2, 2)?), 2)?;
    let invite = InviteRecord {
        channel_id: channel,
        invite_id,
        target: crate::Principal::Account(account_id()),
        inviter_user_id: UserId::from_bytes([9; 16]),
        creation_revision: revision(2),
        expires_at: UtcSecond::from_unix_seconds(600),
    };
    let invited = ProjectedEvent::Invited {
        channel_id: channel,
        invite_id,
        resulting_revision: revision(2),
        local_projection: Some(invite),
        inviter: source(&alice),
        named_target: source(&alice),
    };
    let outcome = replica.apply(&invited, 2)?;
    assert!(outcome.local_recipients.contains(&alice.user_id));
    assert_eq!(replica.apply(&invited, 2), Err(ReplicaError::UnknownEntity));
    let transient = ProjectedEvent::Invited {
        channel_id: channel,
        invite_id: InviteId::from_bytes([4; 16]),
        resulting_revision: revision(2),
        local_projection: None,
        inviter: source(&alice),
        named_target: source(&alice),
    };
    replica.apply(&transient, 2)?;
    assert!(replica.invite(channel, invite_id).is_some());

    let hidden = ProjectedEvent::SessionHidden {
        source: source(&alice),
        last_revision: revision(1),
        kind: SessionHideKind::ClientQuit,
        channels: Vec::new(),
        reason: "bye".to_owned(),
    };
    let outcome = replica.apply(&hidden, 3)?;
    assert!(
        outcome
            .removed
            .contains(&ProjectionKey::session(alice.user_id))
    );
    assert!(
        outcome
            .removed
            .contains(&ProjectionKey::account(account_id()))
    );
    assert!(replica.account(account_id()).is_none());
    let removed = ProjectedEvent::InviteRemoved {
        channel_id: channel,
        invite_id,
        resulting_revision: revision(2),
        kind: crate::federation::record::InviteRemovalKind::ProjectionHidden,
    };
    replica.apply(&removed, 3)?;
    assert_eq!(replica.apply(&removed, 3), Err(ReplicaError::UnknownEntity));
    let hidden_channel = ProjectedEvent::ChannelHidden {
        channel_id: channel,
        last_revision: revision(2),
    };
    replica.apply(&hidden_channel, 3)?;
    assert_eq!(replica.entry_count(), 0);
    Ok(())
}

fn account_record(revision_value: u64) -> Result<AccountRecord, DomainError> {
    Ok(AccountRecord {
        account_id: account_id(),
        account_session_generation: Generation::new(2)?,
        account_revision: revision(revision_value),
    })
}

fn invite_record(channel: u8, invite: u8, target: crate::Principal, rev: u64) -> InviteRecord {
    InviteRecord {
        channel_id: ChannelInstanceId::from_bytes([channel; 16]),
        invite_id: InviteId::from_bytes([invite; 16]),
        target,
        inviter_user_id: UserId::from_bytes([9; 16]),
        creation_revision: revision(rev),
        expires_at: UtcSecond::from_unix_seconds(600),
    }
}

fn invited(record: InviteRecord, inviter: &SessionRecord, rev: u64) -> ProjectedEvent {
    ProjectedEvent::Invited {
        channel_id: record.channel_id,
        invite_id: record.invite_id,
        resulting_revision: revision(rev),
        local_projection: Some(record),
        inviter: source(inviter),
        named_target: source(inviter),
    }
}

#[test]
fn validation_reports_invites_whose_hosting_account_left() -> TestResult {
    let mut replica = EdgeReplica::new(LOCAL);
    let account = Some((account_id(), Generation::new(2)?));
    let alice = session(1, LOCAL, account)?;
    replica.apply(&ProjectedEvent::SessionVisible(view(&alice, true)), 1)?;
    replica.apply(&ProjectedEvent::AccountStateChanged(account_record(1)?), 1)?;
    replica.apply(&ProjectedEvent::ChannelVisible(detail(2, 1)?), 1)?;
    let target = crate::Principal::Account(account_id());
    replica.apply(&invited(invite_record(2, 3, target, 2), &alice, 2), 2)?;
    replica.validate()?;
    let hidden = ProjectedEvent::SessionHidden {
        source: source(&alice),
        last_revision: revision(1),
        kind: SessionHideKind::ClientQuit,
        channels: Vec::new(),
        reason: String::new(),
    };
    replica.apply(&hidden, 3)?;
    assert!(replica.account(account_id()).is_none());
    assert_eq!(replica.validate(), Err(ReplicaError::DanglingReference));
    Ok(())
}

#[test]
fn channel_hidden_refuses_while_only_invites_remain() -> TestResult {
    let mut replica = EdgeReplica::new(LOCAL);
    let alice = session(1, LOCAL, None)?;
    replica.apply(&ProjectedEvent::SessionVisible(view(&alice, true)), 1)?;
    replica.apply(&ProjectedEvent::ChannelVisible(detail(2, 1)?), 1)?;
    let target = crate::Principal::Guest(alice.user_id);
    replica.apply(&invited(invite_record(2, 3, target, 2), &alice, 2), 2)?;
    let hidden = ProjectedEvent::ChannelHidden {
        channel_id: ChannelInstanceId::from_bytes([2; 16]),
        last_revision: revision(2),
    };
    assert_eq!(replica.apply(&hidden, 3), Err(ReplicaError::ChildrenRemain));
    Ok(())
}

#[test]
fn topic_and_recomputation_events_replace_only_known_memberships() -> TestResult {
    let mut replica = EdgeReplica::new(LOCAL);
    let alice = session(1, LOCAL, None)?;
    let bob = session(2, REMOTE, None)?;
    let channel = ChannelInstanceId::from_bytes([2; 16]);
    replica.apply(&ProjectedEvent::SessionVisible(view(&alice, true)), 1)?;
    replica.apply(&ProjectedEvent::ChannelVisible(detail(2, 1)?), 1)?;
    let joined = ProjectedEvent::MemberJoined {
        view: MembershipView {
            membership: membership(2, 1, 2),
            source: source(&alice),
        },
        home_session_revision: Some(revision(2)),
        display_name: DisplayNameValue::prepare("User")?,
    };
    replica.apply(&joined, 2)?;
    let topic = ProjectedEvent::TopicChanged {
        channel_id: channel,
        resulting_revision: revision(3),
        actor: source(&alice),
        topic: None,
    };
    let outcome = replica.apply(&topic, 3)?;
    assert!(outcome.local_recipients.contains(&alice.user_id));
    // A recompute changes the role; the member keeps the revision it joined at.
    let mut promoted = membership(2, 1, 2);
    promoted.role = Role::Owner;
    let recomputed = ProjectedEvent::ChannelMembershipsRecomputed {
        channel_id: channel,
        resulting_revision: revision(4),
        actor: crate::federation::record::ActorView(None),
        memberships: vec![
            MembershipView {
                membership: promoted,
                source: source(&alice),
            },
            MembershipView {
                membership: membership(2, 2, 4),
                source: source(&bob),
            },
        ],
    };
    let outcome = replica.apply(&recomputed, 4)?;
    assert_eq!(
        outcome.upserted,
        vec![
            ProjectionKey::channel_detail(channel),
            ProjectionKey::membership(channel, alice.user_id)
        ]
    );
    assert_eq!(
        replica
            .membership(channel, alice.user_id)
            .map(|record| record.role),
        Some(Role::Owner)
    );
    assert!(replica.membership(channel, bob.user_id).is_none());
    let foreign = ProjectedEvent::ChannelMembershipsRecomputed {
        channel_id: channel,
        resulting_revision: revision(5),
        actor: crate::federation::record::ActorView(None),
        memberships: vec![MembershipView {
            membership: membership(3, 1, 5),
            source: source(&alice),
        }],
    };
    assert_eq!(replica.apply(&foreign, 5), Err(ReplicaError::InvalidRecord));
    Ok(())
}

/// A recompute changes roles only (architecture 13.2): a membership this
/// edge holds keeps the revision it joined at, which its history
/// authorization compares, and the second it joined. A recompute that moves
/// either is refused instead of overwriting the stored membership.
#[test]
fn a_recomputation_that_moves_a_join_revision_or_time_is_refused() -> TestResult {
    let mut replica = EdgeReplica::new(LOCAL);
    let alice = session(1, LOCAL, None)?;
    let channel = ChannelInstanceId::from_bytes([2; 16]);
    replica.apply(&ProjectedEvent::SessionVisible(view(&alice, true)), 1)?;
    replica.apply(&ProjectedEvent::ChannelVisible(detail(2, 1)?), 1)?;
    let joined = ProjectedEvent::MemberJoined {
        view: MembershipView {
            membership: membership(2, 1, 2),
            source: source(&alice),
        },
        home_session_revision: Some(revision(2)),
        display_name: DisplayNameValue::prepare("User")?,
    };
    replica.apply(&joined, 2)?;
    let recompute = |membership| ProjectedEvent::ChannelMembershipsRecomputed {
        channel_id: channel,
        resulting_revision: revision(3),
        actor: crate::federation::record::ActorView(None),
        memberships: vec![MembershipView {
            membership,
            source: source(&alice),
        }],
    };
    let promoted = MembershipRecord {
        role: Role::Operator,
        ..membership(2, 1, 2)
    };
    for moved in [
        // An earlier join revision, which would open older history.
        MembershipRecord {
            membership_revision: revision(1),
            ..promoted
        },
        // The recompute's own revision, as if the member joined just now.
        MembershipRecord {
            membership_revision: revision(3),
            ..promoted
        },
        // Another join second.
        MembershipRecord {
            joined_at: UtcSecond::from_unix_seconds(2),
            ..promoted
        },
    ] {
        let mut probe = replica.clone();
        assert_eq!(
            probe.apply(&recompute(moved), 3),
            Err(ReplicaError::InvalidRecord)
        );
        assert_eq!(
            probe.membership(channel, alice.user_id),
            Some(&membership(2, 1, 2))
        );
    }
    let outcome = replica.apply(&recompute(promoted), 3)?;
    assert!(
        outcome
            .upserted
            .contains(&ProjectionKey::membership(channel, alice.user_id))
    );
    assert_eq!(replica.membership(channel, alice.user_id), Some(&promoted));
    Ok(())
}

#[test]
fn invitations_check_the_inviter_locality_and_the_projection_identity() -> TestResult {
    let mut replica = EdgeReplica::new(LOCAL);
    let alice = session(1, LOCAL, None)?;
    let bob = session(2, REMOTE, None)?;
    replica.apply(&ProjectedEvent::SessionVisible(view(&alice, true)), 1)?;
    replica.apply(&ProjectedEvent::ChannelVisible(detail(2, 1)?), 1)?;
    let guest = crate::Principal::Guest(alice.user_id);
    // A remote inviter is not a local recipient; the hosted target is.
    let outcome = replica.apply(&invited(invite_record(2, 3, guest, 2), &bob, 2), 2)?;
    assert!(!outcome.local_recipients.contains(&bob.user_id));
    assert!(outcome.local_recipients.contains(&alice.user_id));
    let mut mismatched = invited(invite_record(2, 4, guest, 3), &alice, 3);
    if let ProjectedEvent::Invited { invite_id, .. } = &mut mismatched {
        *invite_id = InviteId::from_bytes([5; 16]);
    }
    assert_eq!(
        replica.apply(&mismatched, 3),
        Err(ReplicaError::InvalidRecord)
    );
    let unknown_channel = invited(invite_record(7, 4, guest, 3), &alice, 3);
    assert_eq!(
        replica.apply(&unknown_channel, 3),
        Err(ReplicaError::DanglingReference)
    );
    let unhosted = crate::Principal::Account(account_id());
    let unhosted_target = invited(invite_record(2, 4, unhosted, 3), &alice, 3);
    assert_eq!(
        replica.apply(&unhosted_target, 3),
        Err(ReplicaError::DanglingReference)
    );
    Ok(())
}

#[test]
fn message_delivery_checks_the_target_revision_and_local_parties() -> TestResult {
    use crate::federation::record::{DeliveredMessageRecord, DeliveryTarget};
    let mut replica = EdgeReplica::new(LOCAL);
    let alice = session(1, LOCAL, None)?;
    let bob = session(2, REMOTE, None)?;
    let channel = ChannelInstanceId::from_bytes([2; 16]);
    replica.apply(&ProjectedEvent::SessionVisible(view(&alice, true)), 1)?;
    replica.apply(&ProjectedEvent::ChannelVisible(detail(2, 3)?), 3)?;
    let message = |target: DeliveryTarget, target_revision: u64| {
        ProjectedEvent::MessageDelivered(DeliveredMessageRecord {
            message_id: agenc_relay_types::MessageId::from_bytes([8; 16]),
            kind: crate::MessageKind::Privmsg,
            target,
            sender: source(&alice),
            target_revision: revision(target_revision),
            channel_event_sequence: 4,
            received_unix_milliseconds: 1,
            tags: Vec::new(),
            body: "hi".to_owned(),
        })
    };
    assert_eq!(
        replica.apply(&message(DeliveryTarget::Channel(channel), 2), 4),
        Err(ReplicaError::Revision)
    );
    let outcome = replica.apply(&message(DeliveryTarget::User(bob.user_id), 3), 4)?;
    assert_eq!(
        outcome.local_recipients.into_iter().collect::<Vec<_>>(),
        vec![alice.user_id]
    );
    Ok(())
}

#[test]
fn policy_changes_reject_regressed_or_foreign_revisions() -> TestResult {
    let mut replica = EdgeReplica::new(LOCAL);
    replica.apply(&ProjectedEvent::ChannelVisible(detail(2, 3)?), 3)?;
    assert_eq!(
        replica.apply(&ProjectedEvent::ChannelPolicyChanged(detail(2, 2)?), 4),
        Err(ReplicaError::Revision)
    );
    assert_eq!(
        replica.apply(&ProjectedEvent::ChannelPolicyChanged(detail(2, 4)?), 5),
        Err(ReplicaError::Revision)
    );
    replica.apply(&ProjectedEvent::ChannelPolicyChanged(detail(2, 5)?), 5)?;
    assert_eq!(
        replica
            .channel(ChannelInstanceId::from_bytes([2; 16]))
            .map(|d| d.channel_revision),
        Some(revision(5))
    );
    Ok(())
}

#[test]
fn account_state_accepts_equal_or_newer_revisions() -> TestResult {
    let mut replica = EdgeReplica::new(LOCAL);
    let account = Some((account_id(), Generation::new(2)?));
    let alice = session(1, LOCAL, account)?;
    replica.apply(&ProjectedEvent::SessionVisible(view(&alice, true)), 1)?;
    replica.apply(&ProjectedEvent::AccountStateChanged(account_record(1)?), 1)?;
    replica.apply(&ProjectedEvent::AccountStateChanged(account_record(1)?), 2)?;
    replica.apply(&ProjectedEvent::AccountStateChanged(account_record(3)?), 3)?;
    assert_eq!(
        replica
            .account(account_id())
            .map(|record| record.account_revision),
        Some(revision(3))
    );
    Ok(())
}

#[test]
fn snapshot_rejects_each_malformed_record_shape() -> TestResult {
    let mut replica = EdgeReplica::new(LOCAL);
    let install =
        |replica: &mut EdgeReplica, entries: Vec<ProjectionRecord>| replica.install(1, entries);
    assert_eq!(
        install(
            &mut replica,
            vec![ProjectionRecord::Account(account_record(0)?)]
        ),
        Err(ReplicaError::InvalidRecord)
    );
    let zero_generation = session(1, LOCAL, Some((account_id(), Generation::new(0)?)))?;
    assert_eq!(
        install(
            &mut replica,
            vec![ProjectionRecord::Session(zero_generation)]
        ),
        Err(ReplicaError::InvalidRecord)
    );
    let mut wide_bits = session(1, LOCAL, None)?;
    wide_bits.user_mode_bits = 5;
    assert_eq!(
        install(&mut replica, vec![ProjectionRecord::Session(wide_bits)]),
        Err(ReplicaError::InvalidRecord)
    );
    let mut labelled_guest = session(1, LOCAL, None)?;
    labelled_guest.account_label = Some(crate::AccountLabelValue::parse("guest-label")?);
    assert_eq!(
        install(
            &mut replica,
            vec![ProjectionRecord::Session(labelled_guest)]
        ),
        Err(ReplicaError::InvalidRecord)
    );
    let mut zero_revision = detail(2, 1)?;
    zero_revision.channel_revision = revision(0);
    assert_eq!(
        install(
            &mut replica,
            vec![ProjectionRecord::ChannelDetail(zero_revision)]
        ),
        Err(ReplicaError::InvalidRecord)
    );
    for bits in [0b000, 0b100_0100, 0b01_1100] {
        let mut bad = detail(2, 1)?;
        bad.simple_mode_bits = bits;
        assert_eq!(
            install(&mut replica, vec![ProjectionRecord::ChannelDetail(bad)]),
            Err(ReplicaError::InvalidRecord),
            "{bits:b}"
        );
    }
    Ok(())
}

#[test]
fn session_views_drop_accounts_only_when_no_session_holds_them() -> TestResult {
    let mut replica = EdgeReplica::new(LOCAL);
    let account = Some((account_id(), Generation::new(2)?));
    let alice = session(1, LOCAL, account)?;
    let bob = session(2, LOCAL, account)?;
    replica.apply(&ProjectedEvent::SessionVisible(view(&alice, true)), 1)?;
    replica.apply(&ProjectedEvent::SessionVisible(view(&bob, true)), 1)?;
    replica.apply(&ProjectedEvent::AccountStateChanged(account_record(1)?), 1)?;
    // Alice logs out; Bob still holds the account, so it stays.
    let mut guest_alice = alice.clone();
    guest_alice.account = None;
    guest_alice.session_revision = revision(2);
    let outcome = replica.apply(&ProjectedEvent::SessionVisible(view(&guest_alice, true)), 2)?;
    assert!(outcome.removed.is_empty());
    assert!(replica.account(account_id()).is_some());
    // Bob logs out too; nobody holds the account any more.
    let mut guest_bob = bob.clone();
    guest_bob.account = None;
    guest_bob.session_revision = revision(3);
    let outcome = replica.apply(&ProjectedEvent::SessionVisible(view(&guest_bob, true)), 3)?;
    assert_eq!(outcome.removed, vec![ProjectionKey::account(account_id())]);
    // A session that named an account the replica never stored drops nothing.
    let other = Some((
        AccountId::from_random(AccountRandomId::from_bytes([6; 16])),
        Generation::new(1)?,
    ));
    let carol = session(3, LOCAL, other)?;
    replica.apply(&ProjectedEvent::SessionVisible(view(&carol, true)), 4)?;
    let mut guest_carol = carol.clone();
    guest_carol.account = None;
    guest_carol.session_revision = revision(5);
    let outcome = replica.apply(&ProjectedEvent::SessionVisible(view(&guest_carol, true)), 5)?;
    assert!(outcome.removed.is_empty());
    Ok(())
}

#[test]
fn home_records_must_describe_the_viewed_user() -> TestResult {
    let mut replica = EdgeReplica::new(LOCAL);
    let alice = session(1, LOCAL, None)?;
    let bob = session(2, LOCAL, None)?;
    let crossed = SessionEventView {
        source: alice.source_view(),
        home_projection: Some(bob),
    };
    assert_eq!(
        replica.apply(&ProjectedEvent::SessionVisible(crossed), 1),
        Err(ReplicaError::InvalidRecord)
    );
    Ok(())
}

#[test]
fn session_hidden_requires_ordered_and_complete_channel_lists() -> TestResult {
    let mut replica = EdgeReplica::new(LOCAL);
    let alice = session(1, LOCAL, None)?;
    replica.apply(&ProjectedEvent::SessionVisible(view(&alice, true)), 1)?;
    for channel in [2, 3] {
        replica.apply(&ProjectedEvent::ChannelVisible(detail(channel, 1)?), 1)?;
        let joined = ProjectedEvent::MemberJoined {
            view: MembershipView {
                membership: membership(channel, 1, 2),
                source: source(&alice),
            },
            home_session_revision: Some(revision(2)),
            display_name: DisplayNameValue::prepare("User")?,
        };
        replica.apply(&joined, 2)?;
    }
    let hidden = |channels: Vec<(ChannelInstanceId, Revision)>| ProjectedEvent::SessionHidden {
        source: source(&alice),
        last_revision: revision(2),
        kind: SessionHideKind::ClientQuit,
        channels,
        reason: String::new(),
    };
    let two = ChannelInstanceId::from_bytes([2; 16]);
    let three = ChannelInstanceId::from_bytes([3; 16]);
    assert_eq!(
        replica.apply(&hidden(vec![(three, revision(3)), (two, revision(3))]), 3),
        Err(ReplicaError::SnapshotOrder)
    );
    assert_eq!(
        replica.apply(&hidden(vec![(two, revision(3))]), 3),
        Err(ReplicaError::DanglingReference)
    );
    Ok(())
}

#[test]
fn channel_revision_copies_and_bumps_follow_the_generation_rule() -> TestResult {
    let mut replica = EdgeReplica::new(LOCAL);
    let alice = session(1, LOCAL, None)?;
    let mut ahead = alice.clone();
    ahead.session_revision = revision(5);
    replica.apply(&ProjectedEvent::SessionVisible(view(&ahead, true)), 5)?;
    replica.apply(&ProjectedEvent::ChannelVisible(detail(2, 5)?), 5)?;
    let channel = ChannelInstanceId::from_bytes([2; 16]);
    let hidden = ProjectedEvent::ChannelHidden {
        channel_id: channel,
        last_revision: revision(6),
    };
    assert_eq!(replica.apply(&hidden, 7), Err(ReplicaError::Revision));
    let display_name = DisplayNameValue::prepare("User")?;
    let joined = |membership_revision: u64, home: Option<u64>| ProjectedEvent::MemberJoined {
        view: MembershipView {
            membership: membership(2, 1, membership_revision),
            source: source(&alice),
        },
        home_session_revision: home.map(revision),
        display_name: display_name.clone(),
    };
    // A membership carrying the installed channel revision is accepted even
    // though the generation moved on.
    replica.apply(&joined(5, Some(7)), 7)?;
    assert_eq!(
        replica
            .channel(channel)
            .map(|detail| detail.channel_revision),
        Some(revision(5))
    );
    // A home revision below the session's or away from the generation is refused.
    assert_eq!(
        replica.apply(&joined(8, Some(4)), 8),
        Err(ReplicaError::HomeSessionRevision)
    );
    assert_eq!(
        replica.apply(&joined(8, Some(9)), 8),
        Err(ReplicaError::HomeSessionRevision)
    );
    Ok(())
}

#[test]
fn mode_changes_validate_prefix_and_list_entries() -> TestResult {
    use crate::federation::record::{ModeDirection, ModeListEntryRecord, ProjectedModeChange};
    let mut replica = EdgeReplica::new(LOCAL);
    let alice = session(1, LOCAL, None)?;
    let bob = session(2, REMOTE, None)?;
    let channel = ChannelInstanceId::from_bytes([2; 16]);
    replica.apply(&ProjectedEvent::SessionVisible(view(&alice, true)), 1)?;
    replica.apply(&ProjectedEvent::ChannelVisible(detail(2, 1)?), 1)?;
    let joined = ProjectedEvent::MemberJoined {
        view: MembershipView {
            membership: membership(2, 1, 2),
            source: source(&alice),
        },
        home_session_revision: Some(revision(2)),
        display_name: DisplayNameValue::prepare("User")?,
    };
    replica.apply(&joined, 2)?;
    let prefix = |channel_byte: u8, user: u8, who: &SessionRecord| ProjectedModeChange::Prefix {
        direction: ModeDirection::Add,
        mode_code: 12,
        view: MembershipView {
            membership: membership(channel_byte, user, 3),
            source: source(who),
        },
    };
    let entry = |channel_byte: u8, mode_code: u16| ProjectedModeChange::List {
        direction: ModeDirection::Add,
        entry: ModeListEntryRecord {
            channel_id: ChannelInstanceId::from_bytes([channel_byte; 16]),
            mode_code,
            entry_id: agenc_relay_types::EntryId::from_bytes([7; 16]),
            mask: "*!*@host".to_owned(),
            setter: source(&alice),
            created_at: UtcSecond::from_unix_seconds(1),
            expires_at: None,
        },
    };
    let changed =
        |rev: u64, changes: Vec<ProjectedModeChange>| ProjectedEvent::ChannelModesChanged {
            channel_id: channel,
            resulting_revision: revision(rev),
            actor: crate::federation::record::ActorView(None),
            changes,
        };
    assert_eq!(
        replica.apply(&changed(3, vec![prefix(3, 1, &alice)]), 3),
        Err(ReplicaError::InvalidRecord)
    );
    assert_eq!(
        replica.apply(&changed(3, vec![entry(3, 1)]), 3),
        Err(ReplicaError::InvalidRecord)
    );
    assert_eq!(
        replica.apply(&changed(3, vec![entry(2, 4)]), 3),
        Err(ReplicaError::InvalidRecord)
    );
    let outcome = replica.apply(
        &changed(
            3,
            vec![prefix(2, 1, &alice), prefix(2, 2, &bob), entry(2, 1)],
        ),
        3,
    )?;
    assert_eq!(
        outcome.upserted,
        vec![
            ProjectionKey::channel_detail(channel),
            ProjectionKey::membership(channel, alice.user_id),
        ]
    );
    assert!(replica.membership(channel, bob.user_id).is_none());
    Ok(())
}

/// RUN-08 (issue #134): the two events that bracket a channel are separate,
/// so a correctly running edge holds a channel with no local member between
/// them, and the restore must be able to rebuild that.
///
/// `ChannelVisible` arrives before the `MemberJoined` that entitles the edge
/// to the channel, and `SessionHidden` removes the last local membership
/// while only the coordinator's later `ChannelHidden` removes the channel. A
/// SIGKILL in either window leaves that state durable, and `install` — the
/// snapshot's install, which requires the closure — refused it, which is what
/// refused a killed edge's whole startup. `install_recovered` admits exactly
/// that one relaxation and nothing else.
#[test]
fn a_channel_between_its_bracketing_events_is_admitted_only_by_the_recovered_install() -> TestResult
{
    let alice = session(1, LOCAL, None)?;
    // Sorted by key: sessions, then channel details, then memberships.
    let mut entries = vec![ProjectionRecord::Session(alice.clone())];
    entries.push(ProjectionRecord::ChannelDetail(detail(2, 1)?));
    // Channel 3 is visible with no local member and no invite, which is the
    // state `apply` reaches between `ChannelVisible` and `MemberJoined`.
    entries.push(ProjectionRecord::ChannelDetail(detail(3, 1)?));
    entries.push(ProjectionRecord::Membership(membership(2, 1, 1)));
    entries.sort_by_key(ProjectionRecord::key);

    let mut snapshot = EdgeReplica::new(LOCAL);
    assert_eq!(
        snapshot.install(7, entries.clone()),
        Err(ReplicaError::DanglingReference),
        "a coordinator snapshot must still be closed under entitlement",
    );
    let mut recovered = EdgeReplica::new(LOCAL);
    recovered.install_recovered(7, entries.clone())?;
    assert_eq!(recovered.projection_generation(), 7);
    assert_eq!(recovered.entry_count(), entries.len());

    // The relaxation is exactly one invariant: a child whose parent is absent
    // still refuses both installs.
    let mut dangling = entries.clone();
    dangling.push(ProjectionRecord::Membership(membership(9, 1, 1)));
    dangling.sort_by_key(ProjectionRecord::key);
    assert_eq!(
        EdgeReplica::new(LOCAL).install(7, dangling.clone()),
        Err(ReplicaError::DanglingReference)
    );
    assert_eq!(
        EdgeReplica::new(LOCAL).install_recovered(7, dangling),
        Err(ReplicaError::DanglingReference),
        "a membership whose channel was never projected must still refuse",
    );

    // A membership naming a session the set does not hold refuses as well.
    let mut orphan_member = entries.clone();
    orphan_member.push(ProjectionRecord::Membership(membership(2, 8, 1)));
    orphan_member.sort_by_key(ProjectionRecord::key);
    assert_eq!(
        EdgeReplica::new(LOCAL).install_recovered(7, orphan_member),
        Err(ReplicaError::DanglingReference),
        "a membership whose session is absent must still refuse",
    );

    // An account no session references still refuses, because `apply` drops
    // it with the last session that held it.
    let mut orphan_account = entries;
    orphan_account.push(ProjectionRecord::Account(account_record(1)?));
    orphan_account.sort_by_key(ProjectionRecord::key);
    assert_eq!(
        EdgeReplica::new(LOCAL).install_recovered(7, orphan_account),
        Err(ReplicaError::DanglingReference),
        "an unreferenced account must still refuse",
    );
    Ok(())
}
