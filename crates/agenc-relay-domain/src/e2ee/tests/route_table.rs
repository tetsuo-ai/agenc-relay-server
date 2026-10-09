#![forbid(unsafe_code)]

//! Route table tests: reservations, atomic binding, lock slots, close and
//! recreate isolation, plaintext downgrade rules, recovery gates, and the
//! netjoin collision rule.

use std::error::Error;

use agenc_relay_types::{AccountId, AccountRandomId, ChannelInstanceId};

use super::*;

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn removing_a_projection_releases_only_its_own_target_and_lock_indexes() -> TestResult {
    let pair = DirectPair::new(account(1), account(2))?;
    for target in [RouteTarget::Channel(instance(1)), RouteTarget::Direct(pair)] {
        let mut table = RouteTable::new();
        let first = RouteEntry {
            conversation_id: ConversationId([1; 32]),
            target,
            lock: SemanticLockId([3; 32]),
            lineage: SemanticLockId([3; 32]),
            incarnation: 0,
            binding_id: [4; 32],
            binding_generation: 0,
            lifecycle: RouteLifecycle::Active,
            recovery: RecoveryState::Normal,
        };
        table.restore_entry(first);
        table.remove_projection(&first.conversation_id);
        assert!(table.routes.is_empty());
        assert!(table.by_channel.is_empty());
        assert!(table.by_pair.is_empty());
        assert!(table.locks.is_empty());
        assert!(table.lineages.is_empty());
        // An old lineage can remain beside a successor occupying its
        // target and lock. Removing the old entry must retain that mapping.
        let successor = RouteEntry {
            conversation_id: ConversationId([2; 32]),
            incarnation: 1,
            ..first
        };
        table.restore_entry(first);
        table.restore_entry(successor);
        table.remove_projection(&first.conversation_id);
        table.remove_projection(&first.conversation_id);
        assert_eq!(table.route(&successor.conversation_id), Some(&successor));
        assert_eq!(
            table.locks.get(&first.lock),
            Some(&successor.conversation_id)
        );
        match target {
            RouteTarget::Channel(channel) => {
                assert_eq!(table.channel_route(&channel), Some(&successor))
            }
            RouteTarget::Direct(pair) => assert_eq!(table.direct_route(&pair), Some(&successor)),
        }
    }
    Ok(())
}

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
        lineage: SemanticLockId([lock; 32]),
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

/// The summary of incarnation `incarnation` of lineage `lineage` under its
/// own lock `lock`, naming `predecessor`: every incarnation of a semantic
/// route has its own lock (companion 9.4), and they share the lock of the
/// route's incarnation zero as their lineage.
fn incarnation_summary(
    base: BindingSummary,
    lock: u8,
    lineage: u8,
    incarnation: u64,
    predecessor: [u8; 32],
) -> BindingSummary {
    BindingSummary {
        lock: SemanticLockId([lock; 32]),
        lineage: SemanticLockId([lineage; 32]),
        incarnation,
        predecessor_close_id: predecessor,
        ..base
    }
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
    // So is the next incarnation, under its own lock, while the first is live.
    assert_eq!(
        table.bind(
            ReservationId([2; 16]),
            owner,
            incarnation_summary(summary(2, 1, Some(2), None), 2, 1, 1, [9; 32]),
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
    let base = summary(2, 1, Some(2), None);
    let wrong_predecessor = incarnation_summary(base, 2, 1, 1, [8; 32]);
    assert_eq!(
        table.bind(ReservationId([2; 16]), owner, wrong_predecessor, 50),
        Err(RouteConflict::NotSuccessor)
    );
    // Incarnation zero again, under the closed lock, replays the closed
    // incarnation, and a skipped incarnation is no successor.
    let same_incarnation = incarnation_summary(base, 1, 1, 0, [9; 32]);
    assert_eq!(
        table.bind(ReservationId([2; 16]), owner, same_incarnation, 50),
        Err(RouteConflict::NotSuccessor)
    );
    let skipped = incarnation_summary(base, 3, 1, 2, [9; 32]);
    assert_eq!(
        table.bind(ReservationId([2; 16]), owner, skipped, 50),
        Err(RouteConflict::NotSuccessor)
    );
    let next = incarnation_summary(base, 2, 1, 1, [9; 32]);
    let entry = table.bind(ReservationId([2; 16]), owner, next, 50)?;
    assert_eq!(entry.incarnation, 1);
    assert_eq!(entry.lineage, SemanticLockId([1; 32]));
    assert_eq!(entry.lock, SemanticLockId([2; 32]));
    // The new incarnation now holds the route: its lock again is a fork,
    // and so is the incarnation after it while it is live.
    table.reserve_channel(ReservationId([4; 16]), instance(4), owner, 100)?;
    let repeated = incarnation_summary(summary(4, 1, Some(4), None), 2, 1, 1, [9; 32]);
    assert_eq!(
        table.bind(ReservationId([4; 16]), owner, repeated, 50),
        Err(RouteConflict::ForkedLineage)
    );
    let after = incarnation_summary(summary(4, 1, Some(4), None), 5, 1, 2, [9; 32]);
    assert_eq!(
        table.bind(ReservationId([4; 16]), owner, after, 50),
        Err(RouteConflict::ForkedLineage)
    );
    // A first incarnation under a fresh lock cannot claim a predecessor, and
    // incarnation zero opens only its own lineage.
    table.reserve_channel(ReservationId([3; 16]), instance(3), owner, 100)?;
    let orphan = incarnation_summary(summary(3, 3, Some(3), None), 3, 3, 1, [1; 32]);
    assert_eq!(
        table.bind(ReservationId([3; 16]), owner, orphan, 50),
        Err(RouteConflict::NotSuccessor)
    );
    let misnamed = incarnation_summary(summary(3, 3, Some(3), None), 3, 6, 0, [0; 32]);
    assert_eq!(
        table.bind(ReservationId([3; 16]), owner, misnamed, 50),
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
    assert!(table.channel_route(&instance(1)).is_none());
    assert_eq!(
        table.destroy_channel_instance(&instance(1)),
        Err(RouteConflict::RouteInvalid)
    );
    // The closed route stays the terminal of its lineage without the
    // instance: a fresh instance of the route binds only the next
    // incarnation, naming the close, and never incarnation zero again.
    let closed = table
        .route(&ConversationId([1; 32]))
        .copied()
        .ok_or("the lineage's terminal")?;
    assert_eq!(
        closed.lifecycle,
        RouteLifecycle::Tombstone { close_id: [9; 32] }
    );
    assert!(!table.is_current(&closed.conversation_id));
    table.reserve_channel(ReservationId([2; 16]), instance(2), owner, 100)?;
    assert_eq!(
        table.bind(
            ReservationId([2; 16]),
            owner,
            summary(2, 1, Some(2), None),
            50
        ),
        Err(RouteConflict::NotSuccessor)
    );
    let next = incarnation_summary(summary(2, 1, Some(2), None), 2, 1, 1, [9; 32]);
    assert_eq!(
        table
            .bind(ReservationId([2; 16]), owner, next, 50)?
            .incarnation,
        1
    );
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
        lineage: SemanticLockId([1; 32]),
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

#[test]
fn a_direct_pair_is_reserved_by_at_most_one_reservation_at_a_time() -> TestResult {
    let mut table = RouteTable::new();
    let pair = DirectPair::new(account(1), account(2))?;
    table.reserve_direct(ReservationId([1; 16]), pair, [7; 32], pair.smaller(), 100)?;
    assert_eq!(
        table.reserve_direct(ReservationId([2; 16]), pair, [9; 32], pair.smaller(), 100),
        Err(RouteConflict::GroupConflict)
    );
    assert!(table.direct_plaintext_allowed(&pair));
    Ok(())
}

/// Companion 11.4: "A closed direct binding remains an encrypted tombstone
/// until an explicitly approved new semantic generation is created"; 9.4:
/// "Version 1 therefore permits only one live semantic direct conversation
/// per account pair".
#[test]
fn a_closed_direct_pair_is_reserved_again_for_its_next_incarnation() -> TestResult {
    let mut table = RouteTable::new();
    let pair = DirectPair::new(account(1), account(2))?;
    let creator = pair.smaller();
    table.reserve_direct(ReservationId([1; 16]), pair, [7; 32], creator, 100)?;
    table.bind(
        ReservationId([1; 16]),
        creator,
        summary(1, 1, None, Some(7)),
        50,
    )?;
    let first = ConversationId([1; 32]);
    // The live and the closing incarnation keep the pair.
    assert_eq!(
        table.reserve_direct(ReservationId([2; 16]), pair, [8; 32], creator, 100),
        Err(RouteConflict::GroupConflict)
    );
    table.begin_close(&first)?;
    assert_eq!(
        table.reserve_direct(ReservationId([2; 16]), pair, [8; 32], creator, 100),
        Err(RouteConflict::GroupConflict)
    );
    table.close(&first, [9; 32])?;
    assert!(!table.direct_plaintext_allowed(&pair));
    // After the authorized close the creator reserves the pair again, for
    // one reservation at a time, and only the smaller account does.
    assert_eq!(
        table.reserve_direct(ReservationId([2; 16]), pair, [8; 32], pair.larger(), 100),
        Err(RouteConflict::BadState)
    );
    table.reserve_direct(ReservationId([2; 16]), pair, [8; 32], creator, 100)?;
    assert_eq!(
        table.reserve_direct(ReservationId([3; 16]), pair, [5; 32], creator, 100),
        Err(RouteConflict::GroupConflict)
    );
    // Its binding is the next incarnation naming that close, under its own
    // lock; the closed incarnation's lock and a wrong close are refused.
    let base = summary(2, 1, None, Some(8));
    for refused in [
        incarnation_summary(base, 1, 1, 0, [0; 32]),
        incarnation_summary(base, 2, 1, 1, [4; 32]),
        incarnation_summary(base, 3, 1, 2, [9; 32]),
    ] {
        assert_eq!(
            table.bind(ReservationId([2; 16]), creator, refused, 50),
            Err(RouteConflict::NotSuccessor)
        );
    }
    let second = table.bind(
        ReservationId([2; 16]),
        creator,
        incarnation_summary(base, 2, 1, 1, [9; 32]),
        50,
    )?;
    assert_eq!(table.direct_route(&pair), Some(&second));
    assert!(table.is_current(&second.conversation_id));
    assert!(!table.is_current(&first));
    assert!(!table.direct_plaintext_allowed(&pair));
    // The second incarnation keeps the pair while it is live; its own
    // authorized close frees the pair for the third.
    assert_eq!(
        table.reserve_direct(ReservationId([3; 16]), pair, [5; 32], creator, 100),
        Err(RouteConflict::GroupConflict)
    );
    table.begin_close(&second.conversation_id)?;
    table.close(&second.conversation_id, [10; 32])?;
    table.reserve_direct(ReservationId([3; 16]), pair, [5; 32], creator, 100)?;
    let third = table.bind(
        ReservationId([3; 16]),
        creator,
        incarnation_summary(summary(3, 1, None, Some(5)), 3, 1, 2, [10; 32]),
        50,
    )?;
    assert_eq!(third.incarnation, 2);
    assert_eq!(table.direct_route(&pair), Some(&third));
    Ok(())
}

/// Companion 13.7.1: a route a recovery gate closed "never returns to
/// `normal`"; only the authorized close of a normal route frees its
/// semantic route for the next incarnation here.
#[test]
fn a_tombstone_a_recovery_gate_installed_frees_no_route() -> TestResult {
    let mut table = RouteTable::new();
    let pair = DirectPair::new(account(1), account(2))?;
    let creator = pair.smaller();
    table.reserve_direct(ReservationId([1; 16]), pair, [7; 32], creator, 100)?;
    table.bind(
        ReservationId([1; 16]),
        creator,
        summary(1, 1, None, Some(7)),
        50,
    )?;
    table.reserve_channel(ReservationId([2; 16]), instance(2), creator, 100)?;
    table.bind(
        ReservationId([2; 16]),
        creator,
        summary(2, 2, Some(2), None),
        50,
    )?;
    assert_eq!(table.restore_pending(), 2);
    // Pending keeps the pair.
    assert_eq!(
        table.reserve_direct(ReservationId([3; 16]), pair, [8; 32], creator, 100),
        Err(RouteConflict::GroupConflict)
    );
    table.resolve_recovery(
        &ConversationId([1; 32]),
        RecoveryState::Closed,
        Some([9; 32]),
    )?;
    table.resolve_recovery(
        &ConversationId([2; 32]),
        RecoveryState::Closed,
        Some([6; 32]),
    )?;
    assert_eq!(
        table.reserve_direct(ReservationId([3; 16]), pair, [8; 32], creator, 100),
        Err(RouteConflict::GroupConflict)
    );
    // A fresh channel instance of the closed route cannot bind its next
    // incarnation either.
    table.reserve_channel(ReservationId([4; 16]), instance(4), creator, 100)?;
    assert_eq!(
        table.bind(
            ReservationId([4; 16]),
            creator,
            incarnation_summary(summary(4, 2, Some(4), None), 4, 2, 1, [6; 32]),
            50
        ),
        Err(RouteConflict::NotSuccessor)
    );
    Ok(())
}

/// A lock slot holds one binding: a binding its lineage would admit is a
/// fork while another binding holds its semantic lock, whatever the lineage
/// index names, at incarnation zero and at a later incarnation alike
/// (companion 9.4: the fresh conversation nonce "cannot manufacture a
/// parallel lock slot").
#[test]
fn a_held_lock_slot_admits_no_second_binding_whatever_the_lineage_index() -> TestResult {
    let owner = account(1);
    let closed = RouteEntry {
        conversation_id: ConversationId([1; 32]),
        target: RouteTarget::Channel(instance(1)),
        lock: SemanticLockId([3; 32]),
        lineage: SemanticLockId([3; 32]),
        incarnation: 0,
        binding_id: [4; 32],
        binding_generation: 0,
        lifecycle: RouteLifecycle::Tombstone { close_id: [9; 32] },
        recovery: RecoveryState::Normal,
    };
    // Entries whose lineage disagrees with the lock they hold: incarnation
    // one's lock, and another route's incarnation-zero lock.
    let holders = [
        RouteEntry {
            conversation_id: ConversationId([7; 32]),
            target: RouteTarget::Channel(instance(7)),
            lock: SemanticLockId([5; 32]),
            lineage: SemanticLockId([8; 32]),
            incarnation: 1,
            binding_id: [7; 32],
            lifecycle: RouteLifecycle::Active,
            ..closed
        },
        RouteEntry {
            conversation_id: ConversationId([11; 32]),
            target: RouteTarget::Channel(instance(11)),
            lock: SemanticLockId([12; 32]),
            lineage: SemanticLockId([13; 32]),
            binding_id: [11; 32],
            lifecycle: RouteLifecycle::Active,
            ..closed
        },
    ];
    let next = incarnation_summary(summary(2, 3, Some(2), None), 5, 3, 1, [9; 32]);
    let fresh = summary(2, 12, Some(2), None);
    for (holder, admitted) in holders.into_iter().zip([next, fresh]) {
        let mut table = RouteTable::new();
        table.restore_entry(closed);
        table.reserve_channel(ReservationId([2; 16]), instance(2), owner, 100)?;
        let mut unheld = table.clone();
        assert_eq!(
            unheld
                .bind(ReservationId([2; 16]), owner, admitted, 50)?
                .lock,
            admitted.lock
        );
        table.restore_entry(holder);
        assert_eq!(
            table.bind(ReservationId([2; 16]), owner, admitted, 50),
            Err(RouteConflict::ForkedLineage)
        );
        assert_eq!(table.route(&admitted.conversation_id), None);
    }
    Ok(())
}

/// Restoring the entries of one semantic route in any order indexes its
/// newest incarnation, as the live path did, and keeps a closed channel
/// instance's tombstone on that instance.
#[test]
fn a_restore_in_any_order_indexes_the_newest_route() -> TestResult {
    let pair = DirectPair::new(account(1), account(2))?;
    for target in [
        (RouteTarget::Direct(pair), RouteTarget::Direct(pair)),
        (
            RouteTarget::Channel(instance(1)),
            RouteTarget::Channel(instance(2)),
        ),
    ] {
        let closed = RouteEntry {
            conversation_id: ConversationId([1; 32]),
            target: target.0,
            lock: SemanticLockId([3; 32]),
            lineage: SemanticLockId([3; 32]),
            incarnation: 0,
            binding_id: [4; 32],
            binding_generation: 0,
            lifecycle: RouteLifecycle::Tombstone { close_id: [9; 32] },
            recovery: RecoveryState::Normal,
        };
        let next = RouteEntry {
            conversation_id: ConversationId([2; 32]),
            target: target.1,
            lock: SemanticLockId([5; 32]),
            incarnation: 1,
            binding_id: [6; 32],
            lifecycle: RouteLifecycle::Active,
            ..closed
        };
        for order in [[closed, next], [next, closed]] {
            let mut table = RouteTable::new();
            for entry in order {
                table.restore_entry(entry);
            }
            assert_eq!(
                table.lineages.get(&closed.lineage),
                Some(&next.conversation_id)
            );
            assert_eq!(table.locks.get(&closed.lock), Some(&closed.conversation_id));
            assert_eq!(table.locks.get(&next.lock), Some(&next.conversation_id));
            assert!(table.is_current(&next.conversation_id));
            match (target.0, target.1) {
                (RouteTarget::Direct(pair), _) => {
                    assert_eq!(table.direct_route(&pair), Some(&next));
                    assert!(!table.is_current(&closed.conversation_id));
                }
                (RouteTarget::Channel(old), RouteTarget::Channel(fresh)) => {
                    assert_eq!(table.channel_route(&old), Some(&closed));
                    assert_eq!(table.channel_route(&fresh), Some(&next));
                    assert!(table.is_current(&closed.conversation_id));
                }
                _ => return Err("mixed targets".into()),
            }
            // A further restore of the closed entry, as a recovery gate
            // does, does not take the route back.
            table.restore_entry(closed);
            assert_eq!(
                table.lineages.get(&closed.lineage),
                Some(&next.conversation_id)
            );
        }
    }
    // With both incarnations closed, the later one is the lineage's newest.
    let first_closed = RouteEntry {
        conversation_id: ConversationId([1; 32]),
        target: RouteTarget::Direct(pair),
        lock: SemanticLockId([3; 32]),
        lineage: SemanticLockId([3; 32]),
        incarnation: 0,
        binding_id: [4; 32],
        binding_generation: 0,
        lifecycle: RouteLifecycle::Tombstone { close_id: [9; 32] },
        recovery: RecoveryState::Normal,
    };
    let second_closed = RouteEntry {
        conversation_id: ConversationId([2; 32]),
        lock: SemanticLockId([5; 32]),
        incarnation: 1,
        binding_id: [6; 32],
        lifecycle: RouteLifecycle::Tombstone { close_id: [10; 32] },
        ..first_closed
    };
    for order in [[first_closed, second_closed], [second_closed, first_closed]] {
        let mut table = RouteTable::new();
        for entry in order {
            table.restore_entry(entry);
        }
        assert_eq!(table.direct_route(&pair), Some(&second_closed));
        assert_eq!(
            table.lineages.get(&first_closed.lineage),
            Some(&second_closed.conversation_id)
        );
    }
    // A projected copy, which knows no incarnation, indexes the route that
    // is not a tombstone in either order.
    let tombstone = RouteEntry {
        conversation_id: ConversationId([1; 32]),
        target: RouteTarget::Direct(pair),
        lock: SemanticLockId([3; 32]),
        lineage: SemanticLockId([3; 32]),
        incarnation: 0,
        binding_id: [4; 32],
        binding_generation: 0,
        lifecycle: RouteLifecycle::Tombstone { close_id: [9; 32] },
        recovery: RecoveryState::Normal,
    };
    let live = RouteEntry {
        conversation_id: ConversationId([2; 32]),
        lock: SemanticLockId([5; 32]),
        lineage: SemanticLockId([5; 32]),
        binding_id: [6; 32],
        lifecycle: RouteLifecycle::Active,
        ..tombstone
    };
    for order in [[tombstone, live], [live, tombstone]] {
        let mut table = RouteTable::new();
        for entry in order {
            table.restore_entry(entry);
        }
        assert_eq!(table.direct_route(&pair), Some(&live));
    }
    Ok(())
}
