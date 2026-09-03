#![forbid(unsafe_code)]

//! Edge replica invariants: snapshot install, revision rules, locality, and
//! unreferenced-account cleanup.

use std::error::Error;

use agenc_ircd_types::{
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
