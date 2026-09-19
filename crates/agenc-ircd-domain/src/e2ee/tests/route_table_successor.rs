//! Successor reservations retain route authority and projection ordering.

#![forbid(unsafe_code)]

use super::*;
use agenc_ircd_types::AccountRandomId;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn account(seed: u8) -> AccountId {
    AccountId::from_random(AccountRandomId::from_bytes([seed; 16]))
}

fn entries(target: RouteTarget) -> (RouteEntry, RouteEntry, BindingSummary) {
    let old = RouteEntry {
        conversation_id: ConversationId([1; 32]),
        target,
        lock: SemanticLockId([2; 32]),
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
fn direct_successor_reservations_require_the_owner_nonce_and_exact_lineage() -> TestResult {
    let pair = DirectPair::new(account(1), account(2))?;
    let (old, new, summary) = entries(RouteTarget::Direct(pair));
    let mut routes = RouteTable::new();
    routes.restore_entry(old);
    let id = ReservationId([7; 16]);
    assert_eq!(
        routes.reserve_successor(id, old.conversation_id, pair.larger(), Some([6; 32]), 10),
        Err(RouteConflict::ReservationInvalid)
    );
    routes.reserve_successor(id, old.conversation_id, pair.smaller(), Some([6; 32]), 10)?;
    assert_eq!(
        routes.bind(id, pair.smaller(), summary, 1),
        Err(RouteConflict::BadState)
    );
    assert_eq!(
        routes.bind_successor(id, pair.larger(), summary, 1),
        Err(RouteConflict::ReservationInvalid)
    );
    let wrong = BindingSummary {
        conversation_nonce: Some([8; 32]),
        ..summary
    };
    assert_eq!(
        routes.bind_successor(id, pair.smaller(), wrong, 1),
        Err(RouteConflict::NotSuccessor)
    );
    let genesis = BindingSummary {
        binding_generation: 0,
        previous_binding_id: [0; 32],
        ..summary
    };
    assert_eq!(
        routes.bind_successor(id, pair.smaller(), genesis, 1),
        Err(RouteConflict::NotSuccessor)
    );
    assert_eq!(routes.bind_successor(id, pair.smaller(), summary, 1)?, new);
    assert_eq!(routes.direct_route(&pair), Some(&new));
    assert!(!routes.direct_plaintext_allowed(&pair));
    assert_eq!(routes.route(&old.conversation_id), Some(&old));
    Ok(())
}

#[test]
fn expired_successor_reservations_cannot_replace_the_route() -> TestResult {
    let (old, _, summary) = entries(RouteTarget::Channel(ChannelInstanceId::from_bytes([9; 16])));
    let mut routes = RouteTable::new();
    routes.restore_entry(old);
    let id = ReservationId([7; 16]);
    routes.reserve_successor(id, old.conversation_id, account(1), None, 10)?;
    assert_eq!(
        routes.bind_successor(id, account(1), summary, 10),
        Err(RouteConflict::ReservationInvalid)
    );
    assert_eq!(routes.expire_reservations(10), 1);
    assert_eq!(routes.reservation_predecessor(&id), None);
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
fn successor_reservations_refuse_routes_that_lost_traffic_indexes_or_targets() -> TestResult {
    let channel = ChannelInstanceId::from_bytes([9; 16]);
    let (old, new, _) = entries(RouteTarget::Channel(channel));
    let id = ReservationId([7; 16]);
    let mut routes = RouteTable::new();
    routes.restore_entry(RouteEntry {
        lifecycle: RouteLifecycle::Closing,
        ..old
    });
    assert_eq!(
        routes.reserve_successor(id, old.conversation_id, account(1), None, 10),
        Err(RouteConflict::GroupConflict)
    );
    let mut routes = RouteTable::new();
    routes.restore_entry(old);
    routes.restore_entry(new);
    assert_eq!(
        routes.reserve_successor(id, old.conversation_id, account(1), None, 10),
        Err(RouteConflict::GroupConflict)
    );
    let mut routes = RouteTable::new();
    routes.restore_entry(old);
    routes.reserve_successor(id, old.conversation_id, account(1), None, 10)?;
    assert_eq!(
        routes.reserve_successor(
            ReservationId([8; 16]),
            old.conversation_id,
            account(1),
            None,
            10
        ),
        Err(RouteConflict::GroupConflict)
    );
    Ok(())
}

#[test]
fn binding_a_successor_checks_every_lineage_field() -> TestResult {
    let channel = ChannelInstanceId::from_bytes([9; 16]);
    let other = ChannelInstanceId::from_bytes([10; 16]);
    let (old, new, summary) = entries(RouteTarget::Channel(channel));
    let id = ReservationId([7; 16]);
    let reserved = || -> Result<RouteTable, RouteConflict> {
        let mut routes = RouteTable::new();
        routes.restore_entry(old);
        routes.reserve_successor(id, old.conversation_id, account(1), None, 10)?;
        Ok(routes)
    };
    let stale_routes: [RouteEntry; 4] = [
        RouteEntry {
            lifecycle: RouteLifecycle::Closing,
            ..old
        },
        new,
        RouteEntry {
            target: RouteTarget::Channel(other),
            ..old
        },
        RouteEntry {
            conversation_id: new.conversation_id,
            target: RouteTarget::Channel(other),
            lock: SemanticLockId([9; 32]),
            ..old
        },
    ];
    for stale in stale_routes {
        let mut routes = reserved()?;
        routes.restore_entry(stale);
        assert_eq!(
            routes.bind_successor(id, account(1), summary, 1),
            Err(RouteConflict::NotSuccessor)
        );
    }
    let wrong_summaries = [
        BindingSummary {
            channel_instance_id: None,
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
            previous_binding_id: [9; 32],
            ..summary
        },
    ];
    for wrong in wrong_summaries {
        let mut routes = reserved()?;
        assert_eq!(
            routes.bind_successor(id, account(1), wrong, 1),
            Err(RouteConflict::NotSuccessor)
        );
    }
    let mut routes = reserved()?;
    assert_eq!(routes.bind_successor(id, account(1), summary, 1)?, new);
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
