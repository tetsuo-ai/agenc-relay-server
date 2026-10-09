//! A ReInit activation installs its successor in place of the predecessor's
//! route, and restore keeps the successor's projection.

#![forbid(unsafe_code)]

use super::*;
use agenc_relay_types::AccountRandomId;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn account(seed: u8) -> AccountId {
    AccountId::from_random(AccountRandomId::from_bytes([seed; 16]))
}

fn entries(target: RouteTarget) -> (RouteEntry, RouteEntry, BindingSummary) {
    let old = RouteEntry {
        conversation_id: ConversationId([1; 32]),
        target,
        lock: SemanticLockId([2; 32]),
        lineage: SemanticLockId([2; 32]),
        incarnation: 0,
        binding_id: [3; 32],
        binding_generation: 0,
        lifecycle: RouteLifecycle::Active,
        recovery: RecoveryState::Normal,
    };
    let new = RouteEntry {
        conversation_id: ConversationId([4; 32]),
        binding_id: [5; 32],
        binding_generation: 1,
        ..old
    };
    let summary = BindingSummary {
        conversation_id: new.conversation_id,
        lock: old.lock,
        lineage: old.lineage,
        incarnation: 0,
        predecessor_close_id: [0; 32],
        binding_id: new.binding_id,
        binding_generation: 1,
        previous_binding_id: old.binding_id,
        channel_instance_id: match target {
            RouteTarget::Channel(id) => Some(id),
            _ => None,
        },
        conversation_nonce: match target {
            RouteTarget::Direct(_) => Some([6; 32]),
            _ => None,
        },
    };
    (old, new, summary)
}

#[test]
fn installing_a_successor_replaces_the_route_and_keeps_the_predecessor_entry() -> TestResult {
    for target in [
        RouteTarget::Channel(ChannelInstanceId::from_bytes([9; 16])),
        RouteTarget::Direct(DirectPair::new(account(1), account(2))?),
    ] {
        let (old, new, summary) = entries(target);
        let mut routes = RouteTable::new();
        routes.restore_entry(old);
        assert_eq!(routes.install_successor(old.conversation_id, summary)?, new);
        let projected = match target {
            RouteTarget::Channel(channel) => {
                assert!(!routes.channel_plaintext_allowed(&channel));
                routes.channel_route(&channel)
            }
            RouteTarget::Direct(pair) => {
                assert!(!routes.direct_plaintext_allowed(&pair));
                routes.direct_route(&pair)
            }
        };
        assert_eq!(projected, Some(&new));
        assert_eq!(routes.route(&old.conversation_id), Some(&old));
        assert!(routes.is_current(&new.conversation_id));
        assert!(!routes.is_current(&old.conversation_id));
        // The predecessor no longer owns the route: a second install from it
        // is refused.
        let again = BindingSummary {
            conversation_id: ConversationId([8; 32]),
            ..summary
        };
        assert_eq!(
            routes.install_successor(old.conversation_id, again),
            Err(RouteConflict::NotSuccessor)
        );
    }
    Ok(())
}

#[test]
fn installing_a_successor_checks_every_lineage_field() -> TestResult {
    let channel = ChannelInstanceId::from_bytes([9; 16]);
    let other = ChannelInstanceId::from_bytes([10; 16]);
    let (old, new, summary) = entries(RouteTarget::Channel(channel));
    let mut routes = RouteTable::new();
    assert_eq!(
        routes.install_successor(old.conversation_id, summary),
        Err(RouteConflict::RouteInvalid)
    );
    let stale_routes: [(RouteEntry, Option<RouteEntry>); 4] = [
        (
            RouteEntry {
                lifecycle: RouteLifecycle::Closing,
                ..old
            },
            None,
        ),
        (
            RouteEntry {
                recovery: RecoveryState::Pending,
                ..old
            },
            None,
        ),
        // The successor conversation already has a route.
        (
            old,
            Some(RouteEntry {
                target: RouteTarget::Channel(other),
                lock: SemanticLockId([9; 32]),
                ..new
            }),
        ),
        // Another route took the predecessor's indexes.
        (
            old,
            Some(RouteEntry {
                conversation_id: ConversationId([8; 32]),
                binding_generation: 2,
                ..old
            }),
        ),
    ];
    for (stale, beside) in stale_routes {
        let mut routes = RouteTable::new();
        routes.restore_entry(stale);
        if let Some(beside) = beside {
            routes.restore_entry(beside);
        }
        let before = routes.clone();
        assert_eq!(
            routes.install_successor(old.conversation_id, summary),
            Err(RouteConflict::NotSuccessor)
        );
        assert_eq!(routes, before);
    }
    let wrong_summaries = [
        BindingSummary {
            channel_instance_id: None,
            ..summary
        },
        BindingSummary {
            channel_instance_id: Some(other),
            ..summary
        },
        BindingSummary {
            conversation_nonce: Some([6; 32]),
            ..summary
        },
        BindingSummary {
            lock: SemanticLockId([9; 32]),
            ..summary
        },
        BindingSummary {
            incarnation: 1,
            ..summary
        },
        BindingSummary {
            binding_generation: 0,
            previous_binding_id: [0; 32],
            ..summary
        },
        BindingSummary {
            binding_generation: 2,
            ..summary
        },
        BindingSummary {
            previous_binding_id: [9; 32],
            ..summary
        },
        BindingSummary {
            conversation_id: old.conversation_id,
            ..summary
        },
    ];
    for wrong in wrong_summaries {
        let mut routes = RouteTable::new();
        routes.restore_entry(old);
        assert_eq!(
            routes.install_successor(old.conversation_id, wrong),
            Err(RouteConflict::NotSuccessor)
        );
    }
    // A direct successor names a nonce and no channel instance.
    let pair = DirectPair::new(account(1), account(2))?;
    let (old, _, summary) = entries(RouteTarget::Direct(pair));
    for wrong in [
        BindingSummary {
            conversation_nonce: None,
            ..summary
        },
        BindingSummary {
            channel_instance_id: Some(channel),
            ..summary
        },
    ] {
        let mut routes = RouteTable::new();
        routes.restore_entry(old);
        assert_eq!(
            routes.install_successor(old.conversation_id, wrong),
            Err(RouteConflict::NotSuccessor)
        );
    }
    Ok(())
}

#[test]
fn restoring_predecessor_after_successor_keeps_the_latest_projection() -> TestResult {
    for target in [
        RouteTarget::Channel(ChannelInstanceId::from_bytes([9; 16])),
        RouteTarget::Direct(DirectPair::new(account(1), account(2))?),
    ] {
        let (old, new, _) = entries(target);
        let mut routes = RouteTable::new();
        routes.restore_entry(new);
        routes.restore_entry(old);
        let projected = match target {
            RouteTarget::Channel(channel) => routes.channel_route(&channel),
            RouteTarget::Direct(pair) => routes.direct_route(&pair),
        };
        assert_eq!(projected, Some(&new));
        assert_eq!(routes.route(&old.conversation_id), Some(&old));
    }
    Ok(())
}

#[test]
fn selecting_a_restored_successor_checks_lineage_and_keeps_a_newer_projection() -> TestResult {
    let channel = ChannelInstanceId::from_bytes([9; 16]);
    let other = ChannelInstanceId::from_bytes([10; 16]);
    let (old, new, _) = entries(RouteTarget::Channel(channel));
    let wrong_routes = [
        RouteEntry {
            target: RouteTarget::Channel(other),
            ..new
        },
        RouteEntry {
            lock: SemanticLockId([9; 32]),
            ..new
        },
        RouteEntry {
            incarnation: 1,
            ..new
        },
        RouteEntry {
            binding_generation: 2,
            ..new
        },
    ];
    for wrong in wrong_routes {
        let mut routes = RouteTable::new();
        routes.restore_entry(old);
        routes.restore_entry(wrong);
        assert_eq!(
            routes.select_restored_successor(old.conversation_id, wrong.conversation_id),
            Err(RouteConflict::NotSuccessor)
        );
    }
    let newer = RouteEntry {
        conversation_id: ConversationId([8; 32]),
        binding_id: [8; 32],
        binding_generation: 2,
        ..old
    };
    let mut routes = RouteTable::new();
    routes.restore_entry(old);
    routes.restore_entry(new);
    routes.restore_entry(newer);
    routes.select_restored_successor(old.conversation_id, new.conversation_id)?;
    assert_eq!(routes.channel_route(&channel), Some(&newer));
    let mut routes = RouteTable::new();
    routes.restore_entry(new);
    routes.restore_entry(old);
    routes.select_restored_successor(old.conversation_id, new.conversation_id)?;
    assert_eq!(routes.channel_route(&channel), Some(&new));
    Ok(())
}

/// A route ReInit-migrated at incarnation zero (`P` to `S`), `S` closed by an
/// authorized close, and the route's next incarnation `B` bound naming that
/// close: a restart that restores every entry in any order and then selects
/// `S` over `P` leaves `B` every index it holds, so the restored table is
/// the live one and refuses what it refuses (companion 9.4 and 13.8).
#[test]
fn a_restored_successor_leaves_a_later_incarnation_its_indexes() -> TestResult {
    let pair = DirectPair::new(account(1), account(2))?;
    let owner = pair.smaller();
    let close_id = [77; 32];
    for direct in [false, true] {
        let target = if direct {
            RouteTarget::Direct(pair)
        } else {
            RouteTarget::Channel(ChannelInstanceId::from_bytes([9; 16]))
        };
        let (old, new, summary) = entries(target);
        // Incarnation one under its own lock, in the lineage of incarnation
        // zero, on a fresh channel instance or a fresh direct nonce.
        let next = |conversation: u8, concrete: u8| BindingSummary {
            conversation_id: ConversationId([conversation; 32]),
            lock: SemanticLockId([21; 32]),
            lineage: old.lineage,
            incarnation: 1,
            predecessor_close_id: close_id,
            binding_id: [conversation.wrapping_add(1); 32],
            binding_generation: 0,
            previous_binding_id: [0; 32],
            channel_instance_id: (!direct).then(|| ChannelInstanceId::from_bytes([concrete; 16])),
            conversation_nonce: direct.then_some([concrete; 32]),
        };
        let reserve = |table: &mut RouteTable, id: u8, concrete: u8| {
            if direct {
                table.reserve_direct(ReservationId([id; 16]), pair, [concrete; 32], owner, 1_000)
            } else {
                table.reserve_channel(
                    ReservationId([id; 16]),
                    ChannelInstanceId::from_bytes([concrete; 16]),
                    owner,
                    1_000,
                )
            }
        };
        let mut live = RouteTable::new();
        live.restore_entry(old);
        live.install_successor(old.conversation_id, summary)?;
        live.begin_close(&new.conversation_id)?;
        live.close(&new.conversation_id, close_id)?;
        reserve(&mut live, 1, 66)?;
        let bound = live.bind(ReservationId([1; 16]), owner, next(20, 66), 10)?;
        let restored_entries: Vec<RouteEntry> = live.routes().copied().collect();
        assert_eq!(restored_entries.len(), 3);
        for order in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let mut restored = RouteTable::new();
            for index in order {
                restored.restore_entry(*restored_entries.get(index).ok_or("an entry")?);
            }
            restored.select_restored_successor(old.conversation_id, new.conversation_id)?;
            assert_eq!(restored, live, "direct={direct} order={order:?}");
            assert_eq!(
                restored.lineages.get(&old.lineage),
                Some(&bound.conversation_id)
            );
            assert!(restored.is_current(&bound.conversation_id));
            // A second incarnation one naming the same close is a fork, and
            // the live incarnation keeps a direct pair.
            if direct {
                assert_eq!(restored.direct_route(&pair), Some(&bound));
                assert_eq!(
                    reserve(&mut restored, 2, 67),
                    Err(RouteConflict::GroupConflict)
                );
            } else {
                reserve(&mut restored, 2, 67)?;
                assert_eq!(
                    restored.bind(ReservationId([2; 16]), owner, next(30, 67), 10),
                    Err(RouteConflict::ForkedLineage)
                );
            }
        }
    }
    Ok(())
}
