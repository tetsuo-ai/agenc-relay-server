#![forbid(unsafe_code)]

//! Section 14.6 participation is derived from each current fixed pair, including recovery.

use super::*;

fn bind_pair(
    table: &mut RouteTable,
    pair: DirectPair,
    id: u8,
) -> Result<RouteEntry, RouteConflict> {
    let reservation = ReservationId([id; 16]);
    table.reserve_direct(reservation, pair, [id; 32], pair.smaller(), 100)?;
    let binding = BindingSummary {
        direct_pair: Some(pair),
        ..summary(id, id, None, Some(id))
    };
    table.bind(reservation, pair.smaller(), binding, 50)
}

#[test]
fn both_accounts_remain_on_every_unclosed_pair_across_restart_and_recovery() -> TestResult {
    let [alice, bob, carol, unrelated] = [0, 2, 3, 255].map(account);
    let check =
        |table: &RouteTable| [alice, bob, carol, unrelated].map(|a| table.has_unclosed_direct(a));
    let mut table = RouteTable::new();
    let ab = DirectPair::new(alice, bob)?;
    let bc = DirectPair::new(bob, carol)?;
    let a = bind_pair(&mut table, ab, 1)?;
    let b = bind_pair(&mut table, bc, 2)?;
    assert_eq!(check(&table), [true, true, true, false]);
    table.begin_close(&a.conversation_id)?;
    assert_eq!(check(&table), [true, true, true, false]);
    table.close(&a.conversation_id, [7; 32])?;
    assert_eq!(check(&table), [false, true, true, false]);
    assert!(!table.direct_plaintext_allowed(&ab));
    let mut cold = RouteTable::new();
    for entry in table
        .routes()
        .copied()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        cold.restore_entry(entry);
    }
    assert_eq!(table, cold);
    assert_eq!(cold.restore_pending(), 1);
    assert_eq!(check(&cold), [false, true, true, false]);
    let mut conflict = cold.clone();
    conflict.resolve_recovery(&b.conversation_id, RecoveryState::Conflict, None)?;
    assert_eq!(check(&conflict), [false, true, true, false]);
    cold.resolve_recovery(&b.conversation_id, RecoveryState::Closed, Some([8; 32]))?;
    assert_eq!(check(&cold), [false, false, false, false]);
    assert!(!cold.direct_plaintext_allowed(&bc));
    Ok(())
}

#[test]
fn only_the_current_direct_successor_holds_the_original_pair() -> TestResult {
    let (alice, bob) = (account(1), account(2));
    let pair = DirectPair::new(alice, bob)?;
    let mut table = RouteTable::new();
    let old = bind_pair(&mut table, pair, 1)?;
    let mut channel_table = RouteTable::new();
    let channel = RouteEntry {
        target: RouteTarget::Channel(instance(5)),
        ..old
    };
    channel_table.restore_entry(channel);
    channel_table.restore_entry(RouteEntry {
        binding_generation: 1,
        ..old
    });
    assert_eq!(channel_table.route(&old.conversation_id), Some(&channel));
    assert!(!channel_table.has_unclosed_direct(alice));
    let successor = table.install_successor(
        old.conversation_id,
        BindingSummary {
            binding_generation: 1,
            previous_binding_id: old.binding_id,
            ..summary(2, 1, None, Some(1))
        },
    )?;
    assert!(table.has_unclosed_direct(alice) && table.has_unclosed_direct(bob));
    table.begin_close(&successor.conversation_id)?;
    table.close(&successor.conversation_id, [9; 32])?;
    assert!(
        table
            .route(&old.conversation_id)
            .is_some_and(RouteEntry::accepts_traffic)
    );
    let closed = *table.direct_route(&pair).ok_or("closed successor")?;
    for order in [[old, closed], [closed, old]] {
        let mut cold = RouteTable::new();
        for entry in order {
            cold.restore_entry(entry);
        }
        assert_eq!(table, cold);
        assert!(!cold.has_unclosed_direct(alice) && !cold.has_unclosed_direct(bob));
        cold.restore_entry(RouteEntry {
            target: RouteTarget::Direct(DirectPair::new(alice, account(3))?),
            binding_generation: closed.binding_generation + 1,
            lifecycle: RouteLifecycle::Active,
            ..closed
        });
        assert_eq!(table, cold);
        cold.remove_projection(&closed.conversation_id);
        assert!(cold.has_unclosed_direct(alice) && cold.has_unclosed_direct(bob));
        cold.remove_projection(&old.conversation_id);
        assert!(!cold.has_unclosed_direct(alice) && !cold.has_unclosed_direct(bob));
    }
    Ok(())
}
