#![forbid(unsafe_code)]

//! Route table tests: reservations, atomic binding, lock slots, close and
//! recreate isolation, plaintext downgrade rules, recovery gates, and the
//! netjoin collision rule.

use std::error::Error;

use agenc_ircd_types::{AccountId, AccountRandomId, ChannelInstanceId};

use super::*;

type TestResult = Result<(), Box<dyn Error>>;

fn account(seed: u8) -> AccountId {
    AccountId::from_random(AccountRandomId::from_bytes([seed; 16]))
}

fn instance(seed: u8) -> ChannelInstanceId {
    ChannelInstanceId::from_bytes([seed; 16])
}

fn summary(
    conversation: u8,
    lock: u8,
    instance_seed: Option<u8>,
    nonce: Option<u8>,
) -> BindingSummary {
    BindingSummary {
        conversation_id: ConversationId([conversation; 32]),
        lock: SemanticLockId([lock; 32]),
        incarnation: 0,
        predecessor_close_id: [0; 32],
        binding_id: [conversation.wrapping_add(50); 32],
        binding_generation: 0,
        previous_binding_id: [0; 32],
        channel_instance_id: instance_seed.map(instance),
        conversation_nonce: nonce.map(|seed| [seed; 32]),
    }
}

#[test]
fn direct_pairs_order_by_canonical_account_bytes() -> TestResult {
    let pair = DirectPair::new(account(9), account(1))?;
    assert!(pair.smaller().to_text() < pair.larger().to_text());
    assert_eq!(DirectPair::new(account(1), account(9))?, pair);
    assert!(DirectPair::new(account(1), account(1)).is_err());
    Ok(())
}

#[test]
fn a_channel_binds_through_its_reservation_and_blocks_plaintext() -> TestResult {
    let mut table = RouteTable::new();
    let owner = account(1);
    assert!(table.channel_plaintext_allowed(&instance(1)));
    table.reserve_channel(ReservationId([1; 16]), instance(1), owner, 100)?;
    assert_eq!(
        table.reserve_channel(ReservationId([2; 16]), instance(1), owner, 100),
        Err(RouteConflict::GroupConflict),
        "one reservation per target"
    );
    assert_eq!(
        table.reserve_channel(ReservationId([1; 16]), instance(2), owner, 100),
        Err(RouteConflict::GroupConflict),
        "reservation ids are unique"
    );
    assert!(
        table.channel_plaintext_allowed(&instance(1)),
        "a reservation has no security effect"
    );
    // Wrong owner, expired, wrong target, and wrong generation are refused.
    assert_eq!(
        table.bind(
            ReservationId([1; 16]),
            account(2),
            summary(1, 1, Some(1), None),
            50
        ),
        Err(RouteConflict::ReservationInvalid)
    );
    assert_eq!(
        table.bind(
            ReservationId([1; 16]),
            owner,
            summary(1, 1, Some(1), None),
            100
        ),
        Err(RouteConflict::ReservationInvalid)
    );
    assert_eq!(
        table.bind(
            ReservationId([1; 16]),
            owner,
            summary(1, 1, Some(2), None),
            50
        ),
        Err(RouteConflict::ReservationInvalid)
    );
    assert_eq!(
        table.bind(
            ReservationId([1; 16]),
            owner,
            summary(1, 1, None, Some(3)),
            50
        ),
        Err(RouteConflict::ReservationInvalid)
    );
    let mut later = summary(1, 1, Some(1), None);
    later.binding_generation = 1;
    assert_eq!(
        table.bind(ReservationId([1; 16]), owner, later, 50),
        Err(RouteConflict::BadState)
    );
    let entry = table.bind(
        ReservationId([1; 16]),
        owner,
        summary(1, 1, Some(1), None),
        50,
    )?;
    assert!(entry.accepts_traffic());
    assert_eq!(
        table.reservations().count(),
        0,
        "the reservation is consumed"
    );
    assert!(!table.channel_plaintext_allowed(&instance(1)));
    assert_eq!(table.channel_route(&instance(1)), Some(&entry));
    assert_eq!(table.route(&ConversationId([1; 32])), Some(&entry));
    // The instance is now occupied for reservations too.
    assert_eq!(
        table.reserve_channel(ReservationId([3; 16]), instance(1), owner, 200),
        Err(RouteConflict::GroupConflict)
    );
    Ok(())
}

#[test]
fn a_direct_pair_binds_once_and_only_the_smaller_account_creates() -> TestResult {
    let mut table = RouteTable::new();
    let pair = DirectPair::new(account(1), account(2))?;
    assert_eq!(
        table.reserve_direct(ReservationId([1; 16]), pair, [7; 32], pair.larger(), 100),
        Err(RouteConflict::BadState)
    );
    table.reserve_direct(ReservationId([1; 16]), pair, [7; 32], pair.smaller(), 100)?;
    assert!(table.direct_plaintext_allowed(&pair));
    assert_eq!(
        table.bind(
            ReservationId([1; 16]),
            pair.smaller(),
            summary(1, 1, None, Some(8)),
            50
        ),
        Err(RouteConflict::ReservationInvalid),
        "the nonce must match the reservation"
    );
    let entry = table.bind(
        ReservationId([1; 16]),
        pair.smaller(),
        summary(1, 1, None, Some(7)),
        50,
    )?;
    assert!(!table.direct_plaintext_allowed(&pair));
    assert_eq!(table.direct_route(&pair), Some(&entry));
    assert_eq!(
        table.reserve_direct(ReservationId([2; 16]), pair, [9; 32], pair.smaller(), 100),
        Err(RouteConflict::GroupConflict)
    );
    // An unrelated pair is unaffected.
    let other = DirectPair::new(account(1), account(3))?;
    assert!(table.direct_plaintext_allowed(&other));
    Ok(())
}

#[test]
fn lock_slots_refuse_forks_and_admit_only_the_next_incarnation() -> TestResult {
    let mut table = RouteTable::new();
    let owner = account(1);
    table.reserve_channel(ReservationId([1; 16]), instance(1), owner, 100)?;
    table.bind(
        ReservationId([1; 16]),
        owner,
        summary(1, 1, Some(1), None),
        50,
    )?;
    // A second instance under the same semantic lock while the first is live is a fork.
    table.reserve_channel(ReservationId([2; 16]), instance(2), owner, 100)?;
    assert_eq!(
        table.bind(
            ReservationId([2; 16]),
            owner,
            summary(2, 1, Some(2), None),
            50
        ),
        Err(RouteConflict::ForkedLineage)
    );
    // Close the first lineage.
    assert_eq!(
        table.close(&ConversationId([1; 32]), [9; 32]),
        Err(RouteConflict::BadState),
        "close needs the finalized closing transition first"
    );
    table.begin_close(&ConversationId([1; 32]))?;
    assert!(
        !table
            .route(&ConversationId([1; 32]))
            .is_some_and(RouteEntry::accepts_traffic)
    );
    assert_eq!(
        table.begin_close(&ConversationId([1; 32])),
        Err(RouteConflict::BadState)
    );
    table.close(&ConversationId([1; 32]), [9; 32])?;
    assert!(
        !table.channel_plaintext_allowed(&instance(1)),
        "a tombstone still blocks plaintext"
    );
    // A new incarnation must name the close id and increment.
    let mut wrong_predecessor = summary(2, 1, Some(2), None);
    wrong_predecessor.incarnation = 1;
    wrong_predecessor.predecessor_close_id = [8; 32];
    assert_eq!(
        table.bind(ReservationId([2; 16]), owner, wrong_predecessor, 50),
        Err(RouteConflict::NotSuccessor)
    );
    let mut same_incarnation = summary(2, 1, Some(2), None);
    same_incarnation.predecessor_close_id = [9; 32];
    assert_eq!(
        table.bind(ReservationId([2; 16]), owner, same_incarnation, 50),
        Err(RouteConflict::NotSuccessor)
    );
    let mut next = summary(2, 1, Some(2), None);
    next.incarnation = 1;
    next.predecessor_close_id = [9; 32];
    let entry = table.bind(ReservationId([2; 16]), owner, next, 50)?;
    assert_eq!(entry.incarnation, 1);
    // A first incarnation under a fresh lock cannot claim a predecessor.
    table.reserve_channel(ReservationId([3; 16]), instance(3), owner, 100)?;
    let mut orphan = summary(3, 3, Some(3), None);
    orphan.incarnation = 1;
    orphan.predecessor_close_id = [1; 32];
    assert_eq!(
        table.bind(ReservationId([3; 16]), owner, orphan, 50),
        Err(RouteConflict::NotSuccessor)
    );
    Ok(())
}

#[test]
fn destroying_an_instance_removes_only_its_tombstone() -> TestResult {
    let mut table = RouteTable::new();
    let owner = account(1);
    table.reserve_channel(ReservationId([1; 16]), instance(1), owner, 100)?;
    table.bind(
        ReservationId([1; 16]),
        owner,
        summary(1, 1, Some(1), None),
        50,
    )?;
    assert_eq!(
        table.destroy_channel_instance(&instance(1)),
        Err(RouteConflict::BadState),
        "a live route is never dropped by destruction"
    );
    assert_eq!(
        table.destroy_channel_instance(&instance(4)),
        Err(RouteConflict::RouteInvalid)
    );
    table.begin_close(&ConversationId([1; 32]))?;
    table.close(&ConversationId([1; 32]), [9; 32])?;
    table.destroy_channel_instance(&instance(1))?;
    assert!(table.channel_plaintext_allowed(&instance(1)));
    assert!(table.route(&ConversationId([1; 32])).is_none());
    Ok(())
}

#[test]
fn bindings_are_replaced_only_by_their_successor() -> TestResult {
    let mut table = RouteTable::new();
    let owner = account(1);
    table.reserve_channel(ReservationId([1; 16]), instance(1), owner, 100)?;
    let entry = table.bind(
        ReservationId([1; 16]),
        owner,
        summary(1, 1, Some(1), None),
        50,
    )?;
    let mut successor = summary(1, 1, Some(1), None);
    successor.binding_generation = 1;
    successor.previous_binding_id = entry.binding_id;
    successor.binding_id = [77; 32];
    let mut wrong_previous = successor;
    wrong_previous.previous_binding_id = [3; 32];
    assert_eq!(
        table.replace_binding(&ConversationId([1; 32]), wrong_previous),
        Err(RouteConflict::NotSuccessor)
    );
    let mut wrong_lock = successor;
    wrong_lock.lock = SemanticLockId([4; 32]);
    assert_eq!(
        table.replace_binding(&ConversationId([1; 32]), wrong_lock),
        Err(RouteConflict::NotSuccessor)
    );
    table.replace_binding(&ConversationId([1; 32]), successor)?;
    let replaced = table
        .route(&ConversationId([1; 32]))
        .copied()
        .ok_or("missing route")?;
    assert_eq!(replaced.binding_generation, 1);
    assert_eq!(replaced.binding_id, [77; 32]);
    assert_eq!(
        table.replace_binding(&ConversationId([2; 32]), successor),
        Err(RouteConflict::RouteInvalid)
    );
    table.begin_close(&ConversationId([1; 32]))?;
    assert_eq!(
        table.replace_binding(&ConversationId([1; 32]), successor),
        Err(RouteConflict::BadState)
    );
    Ok(())
}

#[test]
fn the_recovery_gate_only_closes_or_conflicts() -> TestResult {
    let mut table = RouteTable::new();
    let owner = account(1);
    table.reserve_channel(ReservationId([1; 16]), instance(1), owner, 100)?;
    table.bind(
        ReservationId([1; 16]),
        owner,
        summary(1, 1, Some(1), None),
        50,
    )?;
    table.reserve_channel(ReservationId([2; 16]), instance(2), owner, 100)?;
    table.bind(
        ReservationId([2; 16]),
        owner,
        summary(2, 2, Some(2), None),
        50,
    )?;
    table.begin_close(&ConversationId([2; 32]))?;
    table.close(&ConversationId([2; 32]), [9; 32])?;
    assert_eq!(
        table.restore_pending(),
        1,
        "tombstones are already terminal"
    );
    let pending = table
        .route(&ConversationId([1; 32]))
        .copied()
        .ok_or("route")?;
    assert_eq!(pending.recovery, RecoveryState::Pending);
    assert!(!pending.accepts_traffic());
    assert!(!table.channel_plaintext_allowed(&instance(1)));
    assert_eq!(
        table.begin_close(&ConversationId([1; 32])),
        Err(RouteConflict::BadState)
    );
    assert_eq!(
        table.resolve_recovery(&ConversationId([1; 32]), RecoveryState::Normal, None),
        Err(RouteConflict::BadState),
        "a route never returns to normal"
    );
    assert_eq!(
        table.resolve_recovery(&ConversationId([1; 32]), RecoveryState::Closed, None),
        Err(RouteConflict::BadState)
    );
    assert_eq!(
        table.resolve_recovery(&ConversationId([2; 32]), RecoveryState::Conflict, None),
        Err(RouteConflict::BadState)
    );
    table.resolve_recovery(&ConversationId([1; 32]), RecoveryState::Conflict, None)?;
    assert_eq!(
        table
            .route(&ConversationId([1; 32]))
            .map(|entry| entry.recovery),
        Some(RecoveryState::Conflict)
    );
    // A second pending route closes with proven evidence.
    table.reserve_channel(ReservationId([3; 16]), instance(3), owner, 100)?;
    table.bind(
        ReservationId([3; 16]),
        owner,
        summary(3, 3, Some(3), None),
        50,
    )?;
    assert_eq!(table.restore_pending(), 1);
    table.resolve_recovery(
        &ConversationId([3; 32]),
        RecoveryState::Closed,
        Some([5; 32]),
    )?;
    let closed = table
        .route(&ConversationId([3; 32]))
        .copied()
        .ok_or("route")?;
    assert_eq!(closed.recovery, RecoveryState::Closed);
    assert_eq!(
        closed.lifecycle,
        RouteLifecycle::Tombstone { close_id: [5; 32] }
    );
    Ok(())
}

#[test]
fn reservations_expire_and_collisions_have_one_winner() -> TestResult {
    let mut table = RouteTable::new();
    let owner = account(1);
    table.reserve_channel(ReservationId([1; 16]), instance(1), owner, 100)?;
    table.reserve_channel(ReservationId([2; 16]), instance(2), owner, 200)?;
    assert_eq!(table.expire_reservations(100), 1);
    assert_eq!(table.reservations().count(), 1);
    let first = RouteEntry {
        conversation_id: ConversationId([1; 32]),
        target: RouteTarget::Channel(instance(1)),
        lock: SemanticLockId([1; 32]),
        incarnation: 0,
        binding_id: [5; 32],
        binding_generation: 0,
        lifecycle: RouteLifecycle::Active,
        recovery: RecoveryState::Normal,
    };
    let second = RouteEntry {
        conversation_id: ConversationId([2; 32]),
        target: RouteTarget::Channel(instance(2)),
        ..first
    };
    assert_eq!(
        RouteTable::collision_loser(&first, &second),
        second.conversation_id
    );
    assert_eq!(
        RouteTable::collision_loser(&second, &first),
        second.conversation_id
    );
    let same_instance = RouteEntry {
        binding_id: [4; 32],
        conversation_id: ConversationId([3; 32]),
        ..first
    };
    assert_eq!(
        RouteTable::collision_loser(&first, &same_instance),
        first.conversation_id,
        "the smaller binding id wins at equal instances"
    );
    let mut restored = RouteTable::new();
    restored.restore_entry(first);
    assert_eq!(restored.routes().count(), 1);
    assert!(!restored.channel_plaintext_allowed(&instance(1)));
    Ok(())
}
