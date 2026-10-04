#![forbid(unsafe_code)]

//! Applying the reported row changes must reconstruct the resulting replica.

use super::*;
use crate::federation::record::{ActorView, InviteRemovalKind};
use std::collections::{BTreeMap, BTreeSet};

#[test]
fn revision_changes_report_every_surviving_row_once() -> TestResult {
    let alice = session(1, LOCAL, Some((account_id(), Generation::new(2)?)))?;
    let bob = session(2, LOCAL, None)?;
    let remote = session(3, REMOTE, None)?;
    let channel = ChannelInstanceId::from_bytes([7; 16]);
    let invite_id = InviteId::from_bytes([9; 16]);
    let invite = InviteRecord {
        channel_id: channel,
        invite_id,
        target: crate::Principal::Account(account_id()),
        inviter_user_id: alice.user_id,
        creation_revision: revision(3),
        expires_at: UtcSecond::from_unix_seconds(600),
    };
    let mut entries = vec![
        ProjectionRecord::Session(alice.clone()),
        ProjectionRecord::Session(bob.clone()),
        ProjectionRecord::ChannelDetail(detail(7, 3)?),
        ProjectionRecord::Membership(membership(7, 1, 3)),
        ProjectionRecord::Invite(invite),
        ProjectionRecord::Account(AccountRecord {
            account_id: account_id(),
            account_session_generation: Generation::new(2)?,
            account_revision: revision(1),
        }),
    ];
    entries.sort_by_key(ProjectionRecord::key);
    let mut original = EdgeReplica::new(LOCAL);
    original.install(1, entries)?;
    let new_invite = InviteRecord {
        invite_id: InviteId::from_bytes([10; 16]),
        creation_revision: revision(4),
        ..invite
    };
    let cases = vec![
        (
            "local join",
            ProjectedEvent::MemberJoined {
                view: MembershipView {
                    membership: membership(7, 2, 4),
                    source: source(&bob),
                },
                home_session_revision: Some(revision(4)),
                display_name: bob.display_name.clone(),
            },
        ),
        (
            "remote join",
            ProjectedEvent::MemberJoined {
                view: MembershipView {
                    membership: membership(7, 3, 4),
                    source: source(&remote),
                },
                home_session_revision: None,
                display_name: remote.display_name.clone(),
            },
        ),
        (
            "part",
            ProjectedEvent::MemberParted {
                channel_id: channel,
                source: source(&alice),
                resulting_revision: revision(4),
                home_session_revision: Some(revision(4)),
                reason: "left".to_owned(),
            },
        ),
        (
            "kick",
            ProjectedEvent::Kicked {
                channel_id: channel,
                actor: ActorView(None),
                target: source(&alice),
                resulting_revision: revision(4),
                target_home_session_revision: Some(revision(4)),
                reason: "removed".to_owned(),
            },
        ),
        (
            "topic",
            ProjectedEvent::TopicChanged {
                channel_id: channel,
                resulting_revision: revision(4),
                actor: source(&alice),
                topic: None,
            },
        ),
        (
            "membership recomputation",
            ProjectedEvent::ChannelMembershipsRecomputed {
                channel_id: channel,
                resulting_revision: revision(4),
                actor: ActorView(None),
                // A recompute changes the role; the member keeps the
                // revision it joined at.
                memberships: vec![MembershipView {
                    membership: MembershipRecord {
                        role: Role::Operator,
                        ..membership(7, 1, 3)
                    },
                    source: source(&alice),
                }],
            },
        ),
        (
            "modes",
            ProjectedEvent::ChannelModesChanged {
                channel_id: channel,
                resulting_revision: revision(4),
                actor: ActorView(None),
                changes: Vec::new(),
            },
        ),
        (
            "invitation",
            ProjectedEvent::Invited {
                channel_id: channel,
                invite_id: new_invite.invite_id,
                resulting_revision: revision(4),
                local_projection: Some(new_invite),
                inviter: source(&alice),
                named_target: source(&alice),
            },
        ),
        (
            "invitation hosted elsewhere",
            ProjectedEvent::Invited {
                channel_id: channel,
                invite_id: new_invite.invite_id,
                resulting_revision: revision(4),
                local_projection: None,
                inviter: source(&alice),
                named_target: source(&remote),
            },
        ),
        (
            "expired invitation",
            ProjectedEvent::InviteRemoved {
                channel_id: channel,
                invite_id,
                resulting_revision: revision(4),
                kind: InviteRemovalKind::Expired,
            },
        ),
        (
            "hidden invitation",
            ProjectedEvent::InviteRemoved {
                channel_id: channel,
                invite_id,
                resulting_revision: revision(3),
                kind: InviteRemovalKind::ProjectionHidden,
            },
        ),
        (
            "hidden session",
            ProjectedEvent::SessionHidden {
                source: source(&alice),
                last_revision: revision(1),
                kind: SessionHideKind::ClientQuit,
                channels: vec![(channel, revision(4))],
                reason: "left".to_owned(),
            },
        ),
        (
            "destroyed channel",
            ProjectedEvent::ChannelDestroyed {
                channel_id: channel,
                final_revision: revision(4),
            },
        ),
    ];
    let mut omitted = Vec::new();
    for (name, event) in cases {
        let mut replica = original.clone();
        let mut persisted: BTreeMap<_, _> = replica.entries().map(|row| (row.key(), row)).collect();
        let outcome = replica.apply(&event, 4)?;
        let upserts: BTreeSet<_> = outcome.upserted.iter().collect();
        assert_eq!(
            upserts.len(),
            outcome.upserted.len(),
            "duplicate row in {name}"
        );
        for key in &outcome.removed {
            assert!(
                !upserts.contains(key),
                "removed row was also upserted in {name}"
            );
            persisted.remove(key);
        }
        for key in outcome.upserted {
            let row = replica.record(&key).ok_or("reported row was removed")?;
            persisted.insert(key, row);
        }
        let expected: BTreeMap<_, _> = replica.entries().map(|row| (row.key(), row)).collect();
        if persisted != expected {
            omitted.push(name);
        }
    }
    assert!(omitted.is_empty(), "omitted durable mutations: {omitted:?}");
    Ok(())
}

#[test]
fn an_invitation_hosted_elsewhere_advances_the_channel_of_a_member_edge() -> TestResult {
    let alice = session(1, LOCAL, None)?;
    let remote = session(3, REMOTE, None)?;
    let channel = ChannelInstanceId::from_bytes([7; 16]);
    let mut entries = vec![
        ProjectionRecord::Session(alice.clone()),
        ProjectionRecord::ChannelDetail(detail(7, 3)?),
        ProjectionRecord::Membership(membership(7, 1, 3)),
    ];
    entries.sort_by_key(ProjectionRecord::key);
    let mut replica = EdgeReplica::new(LOCAL);
    replica.install(1, entries)?;
    let invited = |channel_id, resulting| ProjectedEvent::Invited {
        channel_id,
        invite_id: InviteId::from_bytes([9; 16]),
        resulting_revision: revision(resulting),
        local_projection: None,
        inviter: source(&alice),
        named_target: source(&remote),
    };
    let outcome = replica.apply(&invited(channel, 4), 4)?;
    assert_eq!(
        outcome.upserted,
        vec![ProjectionKey::channel_detail(channel)]
    );
    assert!(outcome.local_recipients.contains(&alice.user_id));
    assert_eq!(
        replica
            .channel(channel)
            .map(|detail| detail.channel_revision),
        Some(revision(4))
    );
    assert!(
        replica
            .invite(channel, InviteId::from_bytes([9; 16]))
            .is_none()
    );
    assert_eq!(
        replica.apply(&invited(channel, 3), 5),
        Err(ReplicaError::Revision)
    );
    let unknown = ChannelInstanceId::from_bytes([8; 16]);
    assert_eq!(
        replica.apply(&invited(unknown, 5), 5),
        Err(ReplicaError::UnknownEntity)
    );
    replica.validate()?;
    Ok(())
}
