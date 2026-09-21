#![forbid(unsafe_code)]

//! Query cursor bindings, one-slot continuation, expiry, and counters.

use agenc_relay_types::{
    AccountId, AccountRandomId, FederationDirectoryQueryKind, Generation, MonotonicTick, NetworkId,
    ServerId, SessionId, UserId,
};

use super::*;

fn binding(page: u32, counter: u64) -> QueryCursorBinding {
    let generation = Generation::new(1).map_or_else(|_| Generation::new(1).ok(), Some);
    QueryCursorBinding {
        network_id: NetworkId::from_bytes([1; 32]),
        coordinator_server_id: ServerId::from_bytes([2; 16]),
        process_nonce: [3; 16],
        session_id: SessionId::from_bytes([4; 16]),
        user_id: UserId::from_bytes([5; 16]),
        account: generation.map(|generation| {
            (
                AccountId::from_random(AccountRandomId::from_bytes([6; 16])),
                generation,
            )
        }),
        query_kind: FederationDirectoryQueryKind::List,
        query_arm: vec![0, 0],
        state_generation: 9,
        snapshot_token: [7; 32],
        next_page_sequence: page,
        cursor_counter: counter,
    }
}

fn request() -> ContinuationRequest {
    let binding = binding(1, 0);
    ContinuationRequest {
        session_id: binding.session_id,
        user_id: binding.user_id,
        account: binding.account,
        query_kind: binding.query_kind,
        query_arm: binding.query_arm,
    }
}

fn tick(millis: u64) -> MonotonicTick {
    MonotonicTick::from_ticks(millis)
}

#[test]
fn counter_draws_are_unique_and_exhaustion_stops_admission() {
    let mut counter = CursorCounter::default();
    assert_eq!(counter.draw(), Some(0));
    assert_eq!(counter.draw(), Some(1));
    assert_eq!(counter.peek(), 2);
    let mut exhausted = CursorCounter(u64::MAX);
    assert_eq!(exhausted.draw(), None);
    assert_eq!(exhausted.peek(), u64::MAX);
}

#[test]
fn borrowed_continuations_preserve_owned_validation_and_exact_arm_binding()
-> Result<(), CursorRejection> {
    let mut table = QueryCursorTable::new();
    table
        .install_new([1; 32], binding(1, 0), tick(0))
        .map_err(|_| CursorRejection::Unknown)?;
    let owned = request();
    let borrowed = ContinuationRequest {
        session_id: owned.session_id,
        user_id: owned.user_id,
        account: owned.account,
        query_kind: owned.query_kind,
        query_arm: owned.query_arm.as_slice(),
    };
    assert_eq!(
        table.check(&[1; 32], &owned, tick(10))?,
        table.check(&[1; 32], &borrowed, tick(10))?
    );
    let wrong = ContinuationRequest {
        query_arm: [0_u8, 1].as_slice(),
        ..borrowed
    };
    assert_eq!(
        table.check(&[1; 32], &wrong, tick(10)).err(),
        Some(CursorRejection::WrongBinding)
    );
    assert_eq!(
        table.check(&[2; 32], &borrowed, tick(10)).err(),
        Some(CursorRejection::Unknown)
    );
    assert_eq!(
        table.check(&[1; 32], &borrowed, tick(60_000)).err(),
        Some(CursorRejection::Expired)
    );
    assert_eq!(table.len(), 1);
    Ok(())
}

#[test]
fn cursor_table_installs_checks_replaces_and_releases() -> Result<(), CursorRejection> {
    let mut table = QueryCursorTable::new();
    assert!(table.is_empty());
    assert_eq!(table.install_new([1; 32], binding(1, 0), tick(0)), Ok(()));
    assert_eq!(
        table.install_new([1; 32], binding(1, 1), tick(0)),
        Err(CursorCollision)
    );
    assert_eq!(table.len(), 1);
    let live = table.check(&[1; 32], &request(), tick(10))?;
    assert_eq!(live.binding.next_page_sequence, 1);
    assert_eq!(
        table.check(&[2; 32], &request(), tick(10)).err(),
        Some(CursorRejection::Unknown)
    );
    let mut other = request();
    other.session_id = SessionId::from_bytes([9; 16]);
    assert_eq!(
        table.check(&[1; 32], &other, tick(10)).err(),
        Some(CursorRejection::WrongBinding)
    );
    let mut other_account = request();
    other_account.account = None;
    assert_eq!(
        table.check(&[1; 32], &other_account, tick(10)).err(),
        Some(CursorRejection::WrongBinding)
    );
    let mut other_arm = request();
    other_arm.query_arm = vec![1];
    assert_eq!(
        table.check(&[1; 32], &other_arm, tick(10)).err(),
        Some(CursorRejection::WrongBinding)
    );
    let mut other_kind = request();
    other_kind.query_kind = FederationDirectoryQueryKind::Names;
    assert_eq!(
        table.check(&[1; 32], &other_kind, tick(10)).err(),
        Some(CursorRejection::WrongBinding)
    );
    let mut other_user = request();
    other_user.user_id = UserId::from_bytes([9; 16]);
    assert_eq!(
        table.check(&[1; 32], &other_user, tick(10)).err(),
        Some(CursorRejection::WrongBinding)
    );

    table.replace(&[1; 32], Some(([2; 32], binding(2, 1))), tick(50_000))?;
    assert_eq!(
        table.check(&[1; 32], &request(), tick(50_000)).err(),
        Some(CursorRejection::Unknown)
    );
    let successor = table.check(&[2; 32], &request(), tick(109_999))?;
    assert_eq!(successor.created_at, tick(0));
    assert_eq!(successor.last_used_at, tick(50_000));
    assert_eq!(
        table.check(&[2; 32], &request(), tick(110_000)).err(),
        Some(CursorRejection::Expired)
    );
    assert_eq!(
        table.replace(&[9; 32], None, tick(1)),
        Err(CursorRejection::Unknown)
    );
    table
        .install_new([3; 32], binding(1, 2), tick(60_000))
        .map_err(|_| CursorRejection::Unknown)?;
    assert_eq!(
        table.replace(&[2; 32], Some(([3; 32], binding(3, 3))), tick(60_000)),
        Err(CursorRejection::WrongBinding)
    );
    assert_eq!(table.len(), 2);
    table.replace(&[2; 32], None, tick(60_000))?;
    assert_eq!(table.len(), 1);
    assert_eq!(table.release_session(SessionId::from_bytes([4; 16])), 1);
    assert!(table.is_empty());
    Ok(())
}

#[test]
fn absolute_lifetime_expires_despite_activity_and_expire_sweeps() -> Result<(), CursorRejection> {
    let mut table = QueryCursorTable::new();
    table
        .install_new([1; 32], binding(1, 0), tick(0))
        .map_err(|_| CursorRejection::Unknown)?;
    let mut now = 0;
    let mut cursor = [1_u8; 32];
    for page in 2..=11_u32 {
        now += 59_000;
        table.check(&cursor, &request(), tick(now))?;
        let next = [page as u8; 32];
        table.replace(
            &cursor,
            Some((next, binding(page, u64::from(page)))),
            tick(now),
        )?;
        cursor = next;
    }
    assert_eq!(
        table.check(&cursor, &request(), tick(600_000)).err(),
        Some(CursorRejection::Expired)
    );
    assert_eq!(
        table.check(&cursor, &request(), tick(599_999)).map(|_| ()),
        Ok(())
    );
    assert_eq!(table.expire(tick(599_999)), 0);
    assert_eq!(table.expire(tick(600_000)), 1);
    assert!(table.is_empty());
    Ok(())
}
