#![forbid(unsafe_code)]

//! Reply reuse preserves the requester, command, completion, and retention bounds.

use super::*;
use crate::test_support::StateCoreFixture;

#[test]
fn a_reply_is_cached_only_after_completion_and_cannot_cross_routes() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let mut edge = edge();
    let mut request = pending(1, 3, true);
    let key = (1, 0, [9; 32], [7; 32]);
    let command = request.command.clone();
    request.reply_key = Some(key);
    reserve_reply(&mut request)?;
    request.label = Some("first".to_owned());
    request.result.as_mut().ok_or("result")?.completion_event_id = Some([6; 16]);
    edge.pending.insert([5; 16], request);
    assert!(
        edge.render_ready(fixture.context_mut()?, [5; 16])
            .map_err(|e| e.code.to_string())?
            .is_empty()
    );
    assert!(
        edge.replies
            .replay(key, &command, Some("retry"))
            .map_err(|e| e.code.to_string())?
            .is_none()
    );
    edge.pending
        .get_mut(&[5; 16])
        .ok_or("pending")?
        .completion_seen = true;
    assert_eq!(
        edge.render_ready(fixture.context_mut()?, [5; 16])
            .map_err(|e| e.code.to_string())?
            .len(),
        1
    );
    let replay = edge
        .replies
        .replay(key, &command, Some("retry"))
        .map_err(|e| e.code.to_string())?
        .ok_or("reply")?;
    assert_eq!(replay.generation, ConnectionGeneration::new(1));
    // Compare tags and body against the same protocol refusal renderer.
    let body = agenc_relay_e2ee::wire::reply::E2eeReplyCode::Syncing.render_fail("EDIRECT", None);
    let line =
        agenc_relay_e2ee::wire::response::render_labeled_fail("retry", "edge.example", &body)?;
    assert_eq!(
        replay.frames,
        vec![agenc_relay_client_wire::WireMessage::extension_line(&line)?]
    );
    let other = Resolved::Command(ClientCommand::Edirect([8; 32]));
    assert!(edge.replies.replay(key, &other, None).is_err());
    assert!(
        edge.replies
            .replay((2, 0, [9; 32], [7; 32]), &command, None)
            .map_err(|e| e.code.to_string())?
            .is_none()
    );
    assert!(
        edge.replies
            .replay((1, 1, [9; 32], [7; 32]), &command, None)
            .map_err(|e| e.code.to_string())?
            .is_none()
    );
    edge.connection_closed(ConnectionGeneration::new(1));
    assert!(
        edge.replies
            .replay(key, &command, None)
            .map_err(|e| e.code.to_string())?
            .is_none()
    );
    Ok(())
}

#[test]
fn a_kept_reply_lasts_the_retention_and_is_charged_its_size() -> TestResult {
    use crate::budget::{BoundedMemoryCharges, MemoryBudget, MemoryBudgetPort, MemoryCharge};
    let mut replies = super::super::retry::Replies::default();
    let mut request = pending(1, 0, true);
    request.reply_key = Some((1, 0, [9; 32], [7; 32]));
    let reserved = super::super::retry::reply_reservation(&request.command);
    let budget = MemoryBudget::new(reserved);
    request.reservation = Some(
        budget.try_acquire_batch(BoundedMemoryCharges::new(&[MemoryCharge::fixed(reserved)])?)?,
    );
    assert_eq!(budget.available(), 0);
    replies
        .remember(
            &mut request,
            vec![":edge.example EKEY STORED IDENTITY test".to_owned()],
            5,
        )
        .map_err(|e| e.code.to_string())?;
    // The reply keeps its own charge; the rest of the reservation returned.
    let kept = MemoryCharge::allocation(39 + 512)?.bytes();
    assert_eq!(budget.available(), reserved - kept);
    assert!(request.reservation.is_none());
    let until = 5 + agenc_relay_e2ee::limits::RECENT_OBJECT_IDEMPOTENCY_RETENTION_SECONDS;
    replies.expire(until - 1);
    assert!(
        replies
            .replay((1, 0, [9; 32], [7; 32]), &request.command, None)
            .map_err(|e| e.code.to_string())?
            .is_some()
    );
    replies.expire(until);
    assert!(
        replies
            .replay((1, 0, [9; 32], [7; 32]), &request.command, None)
            .map_err(|e| e.code.to_string())?
            .is_none()
    );
    assert_eq!(budget.available(), reserved, "expiry returned its charge");
    // A reply the reservation cannot hold is refused.
    request.reservation =
        Some(budget.try_acquire_batch(BoundedMemoryCharges::new(&[MemoryCharge::fixed(1)])?)?);
    assert!(
        replies
            .remember(
                &mut request,
                vec![":edge.example EKEY STORED".to_owned()],
                5
            )
            .is_err()
    );
    assert_eq!(budget.available(), reserved);
    Ok(())
}

/// The largest reply a submission's command can keep is reserved for it:
/// a live carrier's echo, one line per fragment of its object, or any
/// other submission's one line; a command without an object keeps none.
#[test]
fn a_submission_reserves_the_largest_reply_of_its_command() -> TestResult {
    use super::super::retry::reply_reservation;
    use crate::budget::MemoryCharge;
    use agenc_relay_client_wire::MAX_PHYSICAL_LINE_BYTES;
    use agenc_relay_e2ee::limits::MAX_LIVE_FRAGMENT_COUNT;
    let live = usize::try_from(MAX_LIVE_FRAGMENT_COUNT)?;
    assert_eq!(
        reply_reservation(&Resolved::Command(ClientCommand::Edirect([8; 32]))),
        MemoryCharge::allocation(u64::try_from(
            live * MAX_PHYSICAL_LINE_BYTES + live - 1 + 512
        )?)?
        .bytes()
    );
    assert_eq!(
        reply_reservation(&Resolved::Command(ClientCommand::Ekey(
            agenc_relay_e2ee::wire::command::EkeyCommand::PublishIdentity
        ))),
        MemoryCharge::allocation(u64::try_from(MAX_PHYSICAL_LINE_BYTES + 512)?)?.bytes()
    );
    assert_eq!(
        reply_reservation(&Resolved::Command(ClientCommand::Ekey(
            agenc_relay_e2ee::wire::command::EkeyCommand::Whoami
        ))),
        0
    );
    Ok(())
}

/// Each connection and each account keeps replies within its own quota
/// (companion 16: storage at the ceiling is refused fairly): a connection
/// or an account at its quota is refused, never evicted, and what it keeps
/// never refuses another account's connection.
#[test]
fn replies_are_kept_within_each_connection_and_account_quota() -> TestResult {
    use super::super::retry::{ACCOUNT_REPLIES, CONNECTION_REPLIES, Usage};
    let mut replies = super::super::retry::Replies::default();
    let (one, two, three) = (
        ConnectionGeneration::new(1),
        ConnectionGeneration::new(2),
        ConnectionGeneration::new(3),
    );
    let (account, other) = (account_of(1), account_of(9));
    let reserve = super::super::retry::reply_reservation(&pending(1, 0, true).command);
    let none = (Usage::default(), Usage::default());
    let quota = u32::try_from(CONNECTION_REPLIES)?;
    keep(&mut replies, 1, account, quota - 1)?;
    assert!(replies.admits(one, &account, none, reserve));
    assert!(
        !replies.admits(
            one,
            &account,
            (Usage::default().with(0), Usage::default()),
            reserve
        ),
        "an outstanding submission's reservation counts"
    );
    keep(&mut replies, 1, account, quota)?;
    assert!(
        !replies.admits(one, &account, none, reserve),
        "the connection's quota"
    );
    assert!(
        replies
            .replay((1, 0, [0; 32], [7; 32]), &pending(1, 0, true).command, None)
            .map_err(|e| e.code.to_string())?
            .is_some(),
        "nothing it keeps is evicted"
    );
    // The account's second connection fills the account's quota.
    let rest = u32::try_from(ACCOUNT_REPLIES - CONNECTION_REPLIES)?;
    keep(&mut replies, 2, account, rest - 1)?;
    assert!(replies.admits(two, &account, none, reserve));
    keep(&mut replies, 2, account, rest)?;
    assert!(
        !replies.admits(two, &account, none, reserve),
        "the account's quota"
    );
    assert!(
        !replies.admits(three, &account, none, reserve),
        "every connection of the account"
    );
    assert!(
        replies.admits(three, &other, none, reserve),
        "another account's connection is admitted"
    );
    replies.disconnect(one);
    assert!(
        replies.admits(three, &account, none, reserve),
        "a disconnect releases the account's share of its replies"
    );
    assert!(
        !replies.admits(two, &account, none, reserve),
        "the second connection still holds its own quota"
    );
    Ok(())
}

/// A kept reply's charge counts against its connection's byte quota: a
/// connection keeping few large replies is refused as one keeping many
/// small ones is.
#[test]
fn a_connection_byte_quota_bounds_its_kept_replies() -> TestResult {
    use super::super::retry::{CONNECTION_REPLY_BYTES, Usage};
    let replies = super::super::retry::Replies::default();
    let one = ConnectionGeneration::new(1);
    let account = account_of(1);
    let reserve = super::super::retry::reply_reservation(&pending(1, 0, true).command);
    let outstanding = |bytes: u64| (Usage { replies: 1, bytes }, Usage::default());
    assert!(replies.admits(
        one,
        &account,
        outstanding(CONNECTION_REPLY_BYTES - reserve),
        reserve
    ));
    assert!(!replies.admits(
        one,
        &account,
        outstanding(CONNECTION_REPLY_BYTES - reserve + 1),
        reserve
    ));
    Ok(())
}

/// A kept reply's charge counts against its account's byte quota over all
/// the account's connections: an account whose kept and reserved charges
/// over two connections reach 8 MiB is admitted on a third, and refused one
/// byte past it.
#[test]
fn an_account_byte_quota_bounds_its_kept_replies_over_its_connections() -> TestResult {
    use super::super::retry::{ACCOUNT_REPLY_BYTES, Usage};
    use crate::budget::MemoryCharge;
    let mut replies = super::super::retry::Replies::default();
    let account = account_of(1);
    keep(&mut replies, 1, account, 100)?;
    keep(&mut replies, 2, account, 100)?;
    let line = ":edge.example EKEY STORED IDENTITY x".len() + 512;
    let kept = 200 * MemoryCharge::allocation(u64::try_from(line)?)?.bytes();
    let reserve = super::super::retry::reply_reservation(&pending(1, 0, true).command);
    let outstanding = |bytes: u64| (Usage::default(), Usage { replies: 1, bytes });
    let third = ConnectionGeneration::new(3);
    let room = ACCOUNT_REPLY_BYTES - kept - reserve;
    assert!(replies.admits(third, &account, outstanding(room), reserve));
    assert!(
        !replies.admits(third, &account, outstanding(room + 1), reserve),
        "the account's byte quota"
    );
    Ok(())
}

/// The reservations of an account's outstanding submissions count against
/// its quota over all its connections: an account keeping 1,023 replies
/// over two connections is admitted on a third, and refused with one
/// submission outstanding.
#[test]
fn an_account_outstanding_reservations_count_against_its_quota() -> TestResult {
    use super::super::retry::{ACCOUNT_REPLIES, CONNECTION_REPLIES, Usage};
    let mut replies = super::super::retry::Replies::default();
    let account = account_of(1);
    let quota = u32::try_from(CONNECTION_REPLIES)?;
    keep(&mut replies, 1, account, quota)?;
    keep(
        &mut replies,
        2,
        account,
        u32::try_from(ACCOUNT_REPLIES - CONNECTION_REPLIES)? - 1,
    )?;
    let reserve = super::super::retry::reply_reservation(&pending(1, 0, true).command);
    let third = ConnectionGeneration::new(3);
    let none = (Usage::default(), Usage::default());
    assert!(replies.admits(third, &account, none, reserve));
    assert!(
        !replies.admits(
            third,
            &account,
            (Usage::default(), Usage::default().with(0)),
            reserve
        ),
        "the account's outstanding submission counts"
    );
    Ok(())
}

/// Expiry and a disconnect give a holder's quota back: a connection keeping
/// 512 replies is admitted again once they expire, and neither its usage
/// nor its account's is left behind by expiry or a disconnect.
#[test]
fn expired_and_disconnected_replies_give_their_quota_back() -> TestResult {
    use super::super::retry::{CONNECTION_REPLIES, Usage};
    let mut replies = super::super::retry::Replies::default();
    let one = ConnectionGeneration::new(1);
    let account = account_of(1);
    let reserve = super::super::retry::reply_reservation(&pending(1, 0, true).command);
    let none = (Usage::default(), Usage::default());
    let quota = u32::try_from(CONNECTION_REPLIES)?;
    keep(&mut replies, 1, account, quota)?;
    assert!(!replies.admits(one, &account, none, reserve));
    let until = 5 + agenc_relay_e2ee::limits::RECENT_OBJECT_IDEMPOTENCY_RETENTION_SECONDS;
    replies.expire(until);
    assert!(
        replies.admits(one, &account, none, reserve),
        "admitted again once its replies expire"
    );
    assert_eq!(replies.usage_for_test(1, &account), (None, None));
    keep(&mut replies, 1, account, quota)?;
    assert!(!replies.admits(one, &account, none, reserve));
    replies.disconnect(one);
    assert_eq!(replies.usage_for_test(1, &account), (None, None));
    Ok(())
}

/// An answered submission's reply answers its retries, so its recent-object
/// tuple is released when the reply is published (companion 11.8, 16).
#[test]
fn an_answered_submission_releases_its_recent_object_tuple() -> TestResult {
    use agenc_relay_e2ee::wire::assembly::{Ingest, QuotaScopes};
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let mut edge = edge();
    let mut request = pending(1, 3, true);
    let command = request.command.clone();
    let carrier = command.carrier().ok_or("carrier")?;
    let bytes = vec![0x5a; 64];
    let fragment = agenc_relay_e2ee::wire::fragment::fragment_object(&bytes)?
        .into_iter()
        .next()
        .ok_or("fragment")?;
    let key = (1, 0, *fragment.object_id.as_bytes(), [7; 32]);
    let tuple = super::super::router::submission_key(key, carrier);
    assert_eq!(
        edge.assembler.ingest(
            tuple.clone(),
            QuotaScopes::default(),
            carrier.limit(),
            &fragment,
            0
        )?,
        Ingest::Complete(bytes)
    );
    assert!(edge.assembler.is_recent(&tuple));
    request.reply_key = Some(key);
    reserve_reply(&mut request)?;
    edge.pending.insert([5; 16], request);
    assert_eq!(
        edge.render_ready(fixture.context_mut()?, [5; 16])
            .map_err(|e| e.code.to_string())?
            .len(),
        1
    );
    assert!(!edge.assembler.is_recent(&tuple), "the answer released it");
    assert!(
        edge.replies
            .replay(key, &command, None)
            .map_err(|e| e.code.to_string())?
            .is_some(),
        "its reply answers a retry"
    );
    Ok(())
}
