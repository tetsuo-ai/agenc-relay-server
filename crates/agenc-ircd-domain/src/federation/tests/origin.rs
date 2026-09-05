#![forbid(unsafe_code)]

//! Origin lifecycle: reset, add, update, delete, replay classification,
//! link loss, grace expiry, and incarnation fencing.

use agenc_ircd_types::{
    AccountId, AccountRandomId, ConnectionId, Generation, MonotonicTick, OriginId, RequestId,
    ServerId, ServerIncarnation, SessionId, UserId,
};

use super::*;

const EDGE: ServerId = ServerId::from_bytes([1; 16]);
const INCARNATION: ServerIncarnation = ServerIncarnation::from_bytes([2; 16]);
const NEXT_INCARNATION: ServerIncarnation = ServerIncarnation::from_bytes([3; 16]);

fn key(origin: u8) -> OriginKey {
    OriginKey {
        home_server_id: EDGE,
        server_incarnation: INCARNATION,
        origin_id: OriginId::from_bytes([origin; 16]),
    }
}

fn binding() -> OriginBinding {
    OriginBinding {
        connection_id: ConnectionId::from_bytes([9; 16]),
        connection_nonce: [8; 32],
    }
}

fn add(origin: u8) -> OriginDeclaration {
    OriginDeclaration {
        origin: key(origin),
        generation: 0,
        previous_object_id: [0; 32],
        binding: binding(),
        principal: OriginPrincipal::UNREGISTERED,
        object_id: [origin; 32],
    }
}

fn registered(origin: u8) -> OriginPrincipal {
    OriginPrincipal {
        session: Some((
            SessionId::from_bytes([origin; 16]),
            UserId::from_bytes([origin.wrapping_add(64); 16]),
        )),
        account: None,
    }
}

fn update(
    origin: u8,
    generation: u64,
    previous: [u8; 32],
    principal: OriginPrincipal,
) -> OriginDeclaration {
    OriginDeclaration {
        origin: key(origin),
        generation,
        previous_object_id: previous,
        binding: binding(),
        principal,
        object_id: [origin.wrapping_add(generation as u8); 32],
    }
}

fn operation(origin: u8, generation: u64, sequence: u64) -> OperationKey {
    OperationKey {
        origin: key(origin),
        generation,
        sequence,
    }
}

fn request(seed: u8) -> RequestId {
    RequestId::from_bytes([seed; 16])
}

fn ready_table() -> Result<OriginTable, OriginError> {
    let mut table = OriginTable::new();
    table.reset(EDGE, INCARNATION);
    table.add(add(1))?;
    table.ready(EDGE, INCARNATION)?;
    Ok(table)
}

#[test]
fn retiring_an_exact_replay_identity_preserves_floors_and_matches_restart()
-> Result<(), OriginError> {
    let mut table = ready_table()?;
    let first = operation(1, 0, 0);
    let next = operation(1, 0, 1);
    let id = request(10);
    table.commit_request(first, id)?;
    let entry = table
        .origin(&first.origin)
        .ok_or(OriginError::UnknownOrigin)?;
    assert!(!table.retire_request_id(id, next));
    assert_eq!(
        table.classify_request(next, id, [11; 32], None)?,
        ReplayDecision::RequestIdReuse
    );
    assert!(table.retire_request_id(id, first));
    assert!(!table.retire_request_id(id, first));
    assert_eq!(table.origin(&first.origin), Some(entry));
    assert!(table.request_ids.is_empty());
    let mut restarted = OriginTable::new();
    restarted.restore_edge(
        EDGE,
        table.edge(EDGE).ok_or(OriginError::UnknownIncarnation)?,
    );
    restarted.restore_origin(first.origin, entry);
    for key in [first, next] {
        assert_eq!(
            table.classify_request(key, id, [11; 32], None),
            restarted.classify_request(key, id, [11; 32], None)
        );
    }
    assert_eq!(
        table.classify_request(first, id, [10; 32], None)?,
        ReplayDecision::Expired
    );
    Ok(())
}

#[test]
fn reset_add_ready_and_update_follow_the_declared_lifecycle() -> Result<(), OriginError> {
    let mut table = OriginTable::new();
    assert_eq!(table.add(add(1)), Err(OriginError::UnknownIncarnation));
    table.reset(EDGE, INCARNATION);
    assert_eq!(
        table.edge(EDGE),
        Some(EdgeLink {
            server_incarnation: INCARNATION,
            phase: EdgePhase::Resetting,
        })
    );
    assert_eq!(
        table.ready(EDGE, NEXT_INCARNATION),
        Err(OriginError::UnknownIncarnation)
    );
    table.add(add(1))?;
    table.add(add(1))?;
    let mut conflicting = add(1);
    conflicting.binding.connection_nonce = [7; 32];
    assert_eq!(table.add(conflicting), Err(OriginError::Conflict));
    let mut wrong_generation = add(2);
    wrong_generation.generation = 1;
    assert_eq!(
        table.add(wrong_generation),
        Err(OriginError::InvalidDeclaration)
    );
    assert_eq!(table.update(update(1, 1, [1; 32], registered(1))), Ok(()));
    table.ready(EDGE, INCARNATION)?;
    assert_eq!(table.ready(EDGE, INCARNATION), Err(OriginError::WrongPhase));
    let entry = table.origin(&key(1)).ok_or(OriginError::UnknownOrigin)?;
    assert_eq!(entry.generation, 1);
    assert_eq!(entry.status, OriginStatus::Live);
    assert_eq!(entry.principal, registered(1));
    assert_eq!(table.origins_of(EDGE, INCARNATION).count(), 1);

    assert_eq!(
        table.update(update(1, 3, entry.object_id, registered(1))),
        Err(OriginError::WrongGeneration)
    );
    assert_eq!(
        table.update(update(1, 2, [0; 32], registered(1))),
        Err(OriginError::WrongPredecessor)
    );
    let mut wrong_binding = update(1, 2, entry.object_id, registered(1));
    wrong_binding.binding.connection_id = ConnectionId::from_bytes([1; 16]);
    assert_eq!(
        table.update(wrong_binding),
        Err(OriginError::InvalidDeclaration)
    );
    let account_without_session = OriginPrincipal {
        session: None,
        account: Some((
            AccountId::from_random(AccountRandomId::from_bytes([5; 16])),
            Generation::new(1).map_err(|_| OriginError::Overflow)?,
        )),
    };
    assert_eq!(
        table.update(update(1, 2, entry.object_id, account_without_session)),
        Err(OriginError::InvalidDeclaration)
    );
    let zero_generation_account = OriginPrincipal {
        session: registered(1).session,
        account: Some((
            AccountId::from_random(AccountRandomId::from_bytes([5; 16])),
            Generation::new(0).map_err(|_| OriginError::Overflow)?,
        )),
    };
    assert_eq!(
        table.update(update(1, 2, entry.object_id, zero_generation_account)),
        Err(OriginError::InvalidDeclaration)
    );
    assert_eq!(
        table.update(update(2, 1, [0; 32], registered(2))),
        Err(OriginError::UnknownOrigin)
    );
    assert_eq!(table.update(update(1, 1, [1; 32], registered(1))), Ok(()));
    Ok(())
}

#[test]
fn replay_classification_covers_fresh_duplicate_conflict_gap_expired_and_reuse()
-> Result<(), OriginError> {
    let mut table = ready_table()?;
    let first = operation(1, 0, 0);
    assert_eq!(
        table.classify_request(first, request(10), [10; 32], None),
        Ok(ReplayDecision::Fresh)
    );
    let retained = RetainedRequest {
        request_id: request(10),
        request_object_id: [10; 32],
    };
    assert_eq!(
        table.classify_request(first, request(10), [10; 32], Some(retained)),
        Ok(ReplayDecision::Conflict)
    );
    table.commit_request(first, request(10))?;
    assert_eq!(
        table.commit_request(first, request(10)),
        Err(OriginError::WrongGeneration)
    );
    assert_eq!(
        table.classify_request(first, request(10), [10; 32], Some(retained)),
        Ok(ReplayDecision::ExactDuplicate)
    );
    assert_eq!(
        table.classify_request(first, request(11), [10; 32], Some(retained)),
        Ok(ReplayDecision::Conflict)
    );
    assert_eq!(
        table.classify_request(first, request(10), [11; 32], None),
        Ok(ReplayDecision::Expired)
    );
    assert_eq!(
        table.classify_request(operation(1, 0, 5), request(12), [12; 32], None),
        Ok(ReplayDecision::Gap)
    );
    assert_eq!(
        table.classify_request(operation(1, 0, 1), request(10), [13; 32], None),
        Ok(ReplayDecision::RequestIdReuse)
    );
    assert_eq!(
        table.classify_request(operation(1, 1, 1), request(14), [14; 32], None),
        Err(OriginError::WrongGeneration)
    );
    assert_eq!(
        table.classify_request(operation(2, 0, 0), request(14), [14; 32], None),
        Err(OriginError::UnknownOrigin)
    );
    table.block(&key(1))?;
    assert_eq!(
        table.classify_request(operation(1, 0, 1), request(14), [14; 32], None),
        Err(OriginError::WrongPhase)
    );
    assert_eq!(table.block(&key(2)), Err(OriginError::UnknownOrigin));
    table.fence(&key(1))?;
    assert_eq!(
        table.classify_request(operation(1, 0, 1), request(14), [14; 32], None),
        Err(OriginError::Fenced)
    );
    assert_eq!(table.fence(&key(2)), Err(OriginError::UnknownOrigin));
    Ok(())
}

#[test]
fn delete_is_durable_idempotent_and_final() -> Result<(), OriginError> {
    let mut table = ready_table()?;
    assert_eq!(table.delete(key(2), 0, 0), Err(OriginError::UnknownOrigin));
    assert_eq!(
        table.delete(key(1), 1, 0),
        Err(OriginError::WrongGeneration)
    );
    table.delete(key(1), 0, 4)?;
    table.delete(key(1), 0, 4)?;
    assert_eq!(table.delete(key(1), 0, 5), Err(OriginError::Conflict));
    assert_eq!(
        table.classify_request(operation(1, 0, 4), request(1), [1; 32], None),
        Err(OriginError::Fenced)
    );
    assert_eq!(
        table.update(update(1, 1, [1; 32], registered(1))),
        Err(OriginError::Fenced)
    );
    table.fence(&key(1))?;
    assert_eq!(table.delete(key(1), 0, 4), Err(OriginError::Fenced));
    Ok(())
}

#[test]
fn link_loss_suspends_grace_expiry_fences_and_reset_resumes() -> Result<(), OriginError> {
    let mut table = ready_table()?;
    table.update(update(1, 1, [1; 32], registered(1)))?;
    assert_eq!(
        table.link_lost(EDGE, NEXT_INCARNATION, MonotonicTick::from_ticks(0)),
        Err(OriginError::UnknownIncarnation)
    );
    let deadline = table.link_lost(EDGE, INCARNATION, MonotonicTick::from_ticks(1_000))?;
    assert_eq!(deadline, MonotonicTick::from_ticks(121_000));
    assert_eq!(
        table.origin(&key(1)).map(|entry| entry.status),
        Some(OriginStatus::Suspended)
    );
    assert_eq!(
        table.classify_request(operation(1, 1, 0), request(1), [1; 32], None),
        Err(OriginError::WrongPhase)
    );
    assert_eq!(table.expire(EDGE, MonotonicTick::from_ticks(120_999)), None);
    assert_eq!(
        table.expire(ServerId::from_bytes([7; 16]), MonotonicTick::from_ticks(1)),
        None
    );

    table.reset(EDGE, INCARNATION);
    table.add(add(1))?;
    let current = table.origin(&key(1)).ok_or(OriginError::UnknownOrigin)?;
    table.update(update(1, 1, [1; 32], registered(1)))?;
    assert_eq!(
        table.origin(&key(1)).map(|entry| entry.object_id),
        Some(current.object_id)
    );
    table.ready(EDGE, INCARNATION)?;
    assert_eq!(
        table.origin(&key(1)).map(|entry| entry.status),
        Some(OriginStatus::Live)
    );

    table.link_lost(EDGE, INCARNATION, MonotonicTick::from_ticks(200_000))?;
    let expired = table.expire(EDGE, MonotonicTick::from_ticks(320_000));
    assert_eq!(expired, Some(vec![SessionId::from_bytes([1; 16])]));
    assert_eq!(table.expire(EDGE, MonotonicTick::from_ticks(320_000)), None);
    assert_eq!(
        table.origin(&key(1)).map(|entry| entry.status),
        Some(OriginStatus::Fenced)
    );
    assert_eq!(
        table.link_lost(EDGE, INCARNATION, MonotonicTick::from_ticks(1)),
        Err(OriginError::Fenced)
    );
    assert_eq!(table.add(add(1)), Err(OriginError::WrongPhase));

    table.reset(EDGE, NEXT_INCARNATION);
    let mut next = add(1);
    next.origin.server_incarnation = NEXT_INCARNATION;
    table.add(next)?;
    table.ready(EDGE, NEXT_INCARNATION)?;
    assert_eq!(table.origins_of(EDGE, NEXT_INCARNATION).count(), 1);
    assert_eq!(
        table.origin(&key(1)).map(|entry| entry.status),
        Some(OriginStatus::Fenced)
    );
    Ok(())
}

#[test]
fn restore_rebuilds_durable_rows_without_protocol_checks() -> Result<(), OriginError> {
    let mut table = OriginTable::new();
    table.restore_edge(
        EDGE,
        EdgeLink {
            server_incarnation: INCARNATION,
            phase: EdgePhase::Ready,
        },
    );
    table.restore_origin(
        key(1),
        OriginEntry {
            generation: 2,
            next_sequence: 7,
            object_id: [3; 32],
            binding: binding(),
            principal: registered(1),
            status: OriginStatus::Live,
        },
    );
    table.restore_request_id(request(5), operation(1, 2, 6));
    assert_eq!(
        table.classify_request(operation(1, 2, 7), request(9), [9; 32], None),
        Ok(ReplayDecision::Fresh)
    );
    assert_eq!(
        table.classify_request(operation(1, 2, 7), request(5), [9; 32], None),
        Ok(ReplayDecision::RequestIdReuse)
    );
    let mut fresh = OriginTable::new();
    fresh.restore_edge(
        EDGE,
        EdgeLink {
            server_incarnation: INCARNATION,
            phase: EdgePhase::Expired,
        },
    );
    assert_eq!(fresh.add(add(1)), Err(OriginError::WrongPhase));
    assert_eq!(
        fresh.classify_request(operation(1, 0, 0), request(1), [1; 32], None),
        Err(OriginError::WrongPhase)
    );
    assert_eq!(
        fresh.classify_request(
            OperationKey {
                origin: OriginKey {
                    server_incarnation: NEXT_INCARNATION,
                    ..key(1)
                },
                generation: 0,
                sequence: 0,
            },
            request(1),
            [1; 32],
            None
        ),
        Err(OriginError::UnknownIncarnation)
    );
    Ok(())
}
