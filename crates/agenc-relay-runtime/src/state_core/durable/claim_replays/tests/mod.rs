#![forbid(unsafe_code)]

use super::*;
use crate::budget::MemoryBudget;
use crate::test_support::TestResult;
use agenc_relay_types::AccountRandomId;

fn row(number: usize, expires: u64) -> TestResult<ClaimReplay> {
    let id = u128::try_from(number)?.to_be_bytes();
    let account = u128::try_from(number / PER_ACCOUNT)?.to_be_bytes();
    Ok(ClaimReplay {
        id: RequestId::from_bytes(id),
        account: AccountRandomId::from_bytes(account).to_account_id(),
        expires,
    })
}

fn retain(index: &mut DurableIndex, row: ClaimReplay) -> Result<(), RuntimeError> {
    let held = index.back_claim_replay(row, &[])?;
    index.apply(&[IndexUpdate::RetainClaimReplay(held)]);
    Ok(())
}

#[test]
fn limits_cover_denials_and_successes_by_actual_account_and_globally_until_expiry() -> TestResult {
    let budget = Arc::new(MemoryBudget::new(128 * 1024 * 1024));
    let mut index = DurableIndex::new().with_initial_root_budget(&budget);
    let first = row(0, 99)?;
    let other = row(PER_ACCOUNT, 100)?;
    for n in 0..PER_ACCOUNT {
        retain(&mut index, row(n, if n == 0 { 99 } else { 100 })?)?;
    }
    assert_eq!(
        index.claim_replay_room(first.account, 98),
        Err(RuntimeError::LimitExceeded)
    );
    assert_eq!(index.claim_replay_room(other.account, 98)?, None);
    let charged = budget.charged();
    assert!(charged > 0);
    for n in PER_ACCOUNT..TOTAL {
        retain(&mut index, row(n, 100)?)?;
    }
    let next = row(TOTAL, 200)?;
    assert_eq!(
        index.claim_replay_room(next.account, 98),
        Err(RuntimeError::LimitExceeded)
    );
    assert_eq!(index.claim_replay_room(next.account, 99)?, Some(first.id));
    assert_eq!(index.claim_replay_room(first.account, 99)?, Some(first.id));
    // Another full owner cannot displace the only other account's expired slot.
    assert_eq!(
        index.claim_replay_room(other.account, 99),
        Err(RuntimeError::LimitExceeded)
    );
    assert_eq!(
        index.expired_claim_replays(99, 32).collect::<Vec<_>>(),
        [first.id]
    );
    assert_eq!(index.expired_claim_replays(100, 32).count(), 32);
    let expired = IndexUpdate::RemoveClaimReplay(first.id);
    assert!(matches!(
        index.back_claim_replay(next, &[]),
        Err(RuntimeError::LimitExceeded)
    ));
    let held = index.back_claim_replay(next, std::slice::from_ref(&expired))?;
    assert_eq!(
        index.claim_replay_room(next.account, 98),
        Err(RuntimeError::LimitExceeded)
    );
    index.apply(&[expired, IndexUpdate::RetainClaimReplay(held)]);
    assert_eq!(index.expired_claim_replays(99, 32).count(), 0);
    assert_eq!(
        index.claim_replay_room(first.account, 100)?,
        Some(row(1, 100)?.id)
    );
    drop(index);
    assert_eq!(budget.charged(), 0);
    Ok(())
}

#[test]
fn restoring_a_receipt_requires_process_backing_and_preserves_the_original() -> TestResult {
    let value = row(2, 101)?;
    let unbacked = DurableIndex::new();
    assert!(matches!(
        unbacked.back_claim_replay(value, &[]),
        Err(RuntimeError::MemoryExhausted)
    ));
    let budget = Arc::new(MemoryBudget::new(64 * 1024));
    let mut index = DurableIndex::new().with_initial_root_budget(&budget);
    retain(&mut index, value)?;
    assert!(matches!(
        index.back_claim_replay(value, &[]),
        Err(RuntimeError::InvalidValue)
    ));
    let new = row(3, 101)?;
    let pending = index.back_claim_replay(new, &[])?;
    assert!(matches!(
        index.back_claim_replay(new, &[IndexUpdate::RetainClaimReplay(pending)]),
        Err(RuntimeError::InvalidValue)
    ));
    assert_eq!(
        index.expired_claim_replays(101, 32).collect::<Vec<_>>(),
        [value.id]
    );
    Ok(())
}
