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
