//! Aggregate all pending and durable operations across the same actual peer and originating connection.
#![forbid(unsafe_code)]

use super::*;
use crate::budget::MemoryBudget;
use crate::test_support::TestResult;
use agenc_relay_federation_wire::ReplayKey;
use agenc_relay_types::{OriginId, ServerId, ServerIncarnation};

fn key(peer: usize, origin: usize, seq: usize) -> TestResult<Key> {
    Ok(ReplayKey {
        home_server_id: ServerId::from_bytes(u128::try_from(peer)?.to_be_bytes()),
        server_incarnation: ServerIncarnation::from_bytes([42; 16]),
        origin_id: OriginId::from_bytes(u128::try_from(origin)?.to_be_bytes()),
        origin_generation: 1,
        operation_sequence: u64::try_from(seq)?,
    }
    .to_bytes())
}
fn row(raw: Key) -> Mapping {
    Mapping {
        key: raw,
        digest: [33; 32],
        deadline: WEEK,
        closing: false,
    }
}

#[test]
fn origin_peer_and_process_ceilings_include_pending_and_durable_exact_results() -> TestResult {
    let budget = Arc::new(MemoryBudget::new(64 * 1024 * 1024));
    let mut index = DurableIndex::new().with_initial_root_budget(&budget);
    let pending = key(0, 0, 0)?;
    let next = key(0, 0, PER_ORIGIN)?;
    assert_eq!(
        index.require_federated_claim_room(&pending, [&pending]),
        Err(RuntimeError::InvalidValue)
    );
    for n in 1..PER_ORIGIN {
        let raw = key(0, 0, n)?;
        let held = index.back_federated_claim(row(raw))?;
        index.apply(&[IndexUpdate::RetainFederatedClaim(held)]);
    }
    assert_eq!(
        index.require_federated_claim_room(&next, [&pending]),
        Err(RuntimeError::LimitExceeded)
    );
    index.require_federated_claim_room(&next, [])?;
    let held = index.back_federated_claim(row(pending))?;
    index.apply(&[IndexUpdate::RetainFederatedClaim(held)]);
    for n in PER_ORIGIN..TOTAL {
        let raw = key(n / PER_PEER, n / PER_ORIGIN, n % PER_ORIGIN)?;
        index.require_federated_claim_room(&raw, [])?;
        let held = index.back_federated_claim(row(raw))?;
        index.apply(&[IndexUpdate::RetainFederatedClaim(held)]);
        if n + 1 == PER_PEER {
            assert_eq!(
                index.require_federated_claim_room(&key(0, 999, 0)?, []),
                Err(RuntimeError::LimitExceeded)
            );
            index.require_federated_claim_room(&key(1, 0, 0)?, [])?;
        }
    }
    let last = key(99, 999, 0)?;
    assert_eq!(
        index.require_federated_claim_room(&last, []),
        Err(RuntimeError::LimitExceeded)
    );
    assert!(index.federated_claim(&pending).is_some());
    assert!(budget.charged() > 0);
    drop(index);
    assert_eq!(budget.charged(), 0);
    Ok(())
}
