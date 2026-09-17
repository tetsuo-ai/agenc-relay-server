#![forbid(unsafe_code)]

//! COV-01: the edge replica reference checks the Stage 10 branch report
//! recorded as never taken.
//!
//! Each case installs or applies through the real `EdgeReplica` boundary and
//! re-reads the replica afterwards, so a refused snapshot or event is proved to
//! leave the standing generation and its entries untouched.

use super::*;

/// A membership whose channel is present but whose session is not dangles, and
/// the refused snapshot never replaces the standing generation.
#[test]
fn a_membership_without_its_session_dangles_and_keeps_the_standing_snapshot() -> TestResult {
    let mut replica = EdgeReplica::new(LOCAL);
    let alice = session(1, LOCAL, None)?;
    replica.install(
        4,
        vec![
            ProjectionRecord::Session(alice.clone()),
            ProjectionRecord::ChannelDetail(detail(2, 3)?),
            ProjectionRecord::Membership(membership(2, 1, 3)),
        ],
    )?;
    assert_eq!(replica.entry_count(), 3);

    // The channel resolves, so only the membership's own session reference can
    // dangle; the refusal must come from that second reference.
    assert_eq!(
        replica.install(
            5,
            vec![
                ProjectionRecord::ChannelDetail(detail(2, 3)?),
                ProjectionRecord::Membership(membership(2, 1, 3)),
            ],
        ),
        Err(ReplicaError::DanglingReference)
    );
    assert_eq!(replica.projection_generation(), 4);
    assert_eq!(replica.entry_count(), 3);
    assert!(
        replica
            .membership(ChannelInstanceId::from_bytes([2; 16]), alice.user_id)
            .is_some()
    );
    Ok(())
}

/// An invite whose channel is absent dangles even though its target is hosted,
/// and the refused snapshot never replaces the standing generation.
#[test]
fn an_invite_without_its_channel_dangles_and_keeps_the_standing_snapshot() -> TestResult {
    let mut replica = EdgeReplica::new(LOCAL);
    let alice = session(1, LOCAL, None)?;
    replica.install(6, vec![ProjectionRecord::Session(alice.clone())])?;
    let hosted = crate::Principal::Guest(alice.user_id);

    assert_eq!(
        replica.install(
            7,
            vec![
                ProjectionRecord::Session(alice.clone()),
                ProjectionRecord::Invite(invite_record(7, 3, hosted, 2)),
            ],
        ),
        Err(ReplicaError::DanglingReference)
    );
    assert_eq!(replica.projection_generation(), 6);
    assert_eq!(replica.entry_count(), 1);
    assert!(
        replica
            .invite(
                ChannelInstanceId::from_bytes([7; 16]),
                InviteId::from_bytes([3; 16])
            )
            .is_none()
    );
    Ok(())
}

/// An `Invited` event whose standing copy names another channel is refused as
/// an invalid record, before any dangling-reference or duplicate check.
#[test]
fn an_invited_projection_must_name_its_own_channel() -> TestResult {
    let mut replica = EdgeReplica::new(LOCAL);
    let alice = session(1, LOCAL, None)?;
    replica.apply(&ProjectedEvent::SessionVisible(view(&alice, true)), 1)?;
    replica.apply(&ProjectedEvent::ChannelVisible(detail(2, 1)?), 1)?;
    let hosted = crate::Principal::Guest(alice.user_id);

    // The record names channel 2; the event names channel 3, which is neither
    // installed nor the record's channel.
    let mut mismatched = invited(invite_record(2, 4, hosted, 2), &alice, 2);
    if let ProjectedEvent::Invited { channel_id, .. } = &mut mismatched {
        *channel_id = ChannelInstanceId::from_bytes([3; 16]);
    }
    assert_eq!(
        replica.apply(&mismatched, 2),
        Err(ReplicaError::InvalidRecord)
    );
    assert!(
        replica
            .invite(
                ChannelInstanceId::from_bytes([2; 16]),
                InviteId::from_bytes([4; 16])
            )
            .is_none()
    );

    // The same record under its own channel installs.
    replica.apply(&invited(invite_record(2, 4, hosted, 2), &alice, 2), 2)?;
    assert!(
        replica
            .invite(
                ChannelInstanceId::from_bytes([2; 16]),
                InviteId::from_bytes([4; 16])
            )
            .is_some()
    );
    Ok(())
}

/// A direct message from a remote sender to a hosted recipient delivers to the
/// recipient alone: the replica never invents a local copy for a sender it does
/// not host.
#[test]
fn a_direct_message_from_a_remote_sender_reaches_only_its_hosted_recipient() -> TestResult {
    use crate::federation::record::{DeliveredMessageRecord, DeliveryTarget};
    let mut replica = EdgeReplica::new(LOCAL);
    let alice = session(1, LOCAL, None)?;
    let bob = session(2, REMOTE, None)?;
    replica.apply(&ProjectedEvent::SessionVisible(view(&alice, true)), 1)?;
    replica.apply(&ProjectedEvent::SessionVisible(view(&bob, false)), 1)?;
    let message = |sender: &SessionRecord, target: DeliveryTarget| {
        ProjectedEvent::MessageDelivered(DeliveredMessageRecord {
            message_id: agenc_ircd_types::MessageId::from_bytes([9; 16]),
            kind: crate::MessageKind::Privmsg,
            target,
            sender: source(sender),
            target_revision: revision(0),
            channel_event_sequence: 0,
            received_unix_milliseconds: 1,
            tags: Vec::new(),
            body: "hi".to_owned(),
        })
    };

    let outcome = replica.apply(&message(&bob, DeliveryTarget::User(alice.user_id)), 2)?;
    assert_eq!(
        outcome.local_recipients.into_iter().collect::<Vec<_>>(),
        vec![alice.user_id]
    );

    // Neither end is hosted here, so the edge delivers nothing at all.
    let remote_only = session(3, REMOTE, None)?;
    replica.apply(
        &ProjectedEvent::SessionVisible(view(&remote_only, false)),
        2,
    )?;
    let outcome = replica.apply(&message(&bob, DeliveryTarget::User(remote_only.user_id)), 2)?;
    assert!(outcome.local_recipients.into_iter().next().is_none());
    Ok(())
}
