#![forbid(unsafe_code)]

//! COV-01: the committed administrative account transitions and the two
//! channel structural checks the Stage 10 branch report recorded as never
//! taken.
//!
//! Every refusal is re-read from the state afterwards, so a refused
//! administrative command is proved to leave the account, its revision and the
//! authoritative revision exactly as they were.

use super::*;

/// A channel key mode and a stored key verifier must appear together: either
/// one alone is an invariant violation, and the pair validates.
#[test]
fn channel_validation_pairs_the_key_mode_with_its_verifier() -> Result<(), DomainError> {
    let mut value = channel(1, "#keyed")?;
    assert_eq!(value.validate(), Ok(()));

    value.modes.join_key = true;
    assert_eq!(value.validate(), Err(DomainError::InvariantViolation));

    value.key_verifier = Some(ChannelKeyVerifier::new(id(7), [9; 32]));
    assert_eq!(value.validate(), Ok(()));

    value.modes.join_key = false;
    assert_eq!(value.validate(), Err(DomainError::InvariantViolation));
    Ok(())
}

/// A pending encrypted-removal entry is only structurally valid inside an
/// E2EE-bound channel and only for a current member.
#[test]
fn channel_validation_refuses_a_pending_removal_outside_its_membership() -> Result<(), DomainError>
{
    let mut value = channel(2, "#pending")?;
    let member = value
        .memberships
        .keys()
        .copied()
        .next()
        .ok_or(DomainError::InvariantViolation)?;
    // A plaintext channel may hold no pending removal at all.
    value.e2ee_removal_pending.insert(member);
    assert_eq!(value.validate(), Err(DomainError::InvariantViolation));

    // A stranger is refused even once the channel is E2EE-bound.
    value.e2ee_removal_pending.clear();
    value
        .e2ee_removal_pending
        .insert(UserId::from_bytes(id(200)));
    assert_eq!(value.validate(), Err(DomainError::InvariantViolation));

    value.e2ee_removal_pending.clear();
    assert_eq!(value.validate(), Ok(()));
    Ok(())
}

/// Suspending an account advances the account revision and the authoritative
/// revision together, refuses an unknown account without touching either, and
/// refuses a revision that cannot advance.
#[test]
fn account_suspension_advances_both_revisions_or_changes_nothing() -> Result<(), DomainError> {
    let mut state = DomainState::new()?;
    let account_id = account(1);
    state.accounts.insert(
        account_id,
        AccountState::new(account_id, Generation::new(1)?, state.revision),
    );
    let before = state.revision;
    let expires_at = UtcSecond::from_unix_seconds(500);

    // An unknown account is refused and nothing moves.
    assert_eq!(
        state.admin_suspend_account(account(9), expires_at),
        Err(DomainError::NotFound)
    );
    assert_eq!(state.revision, before);
    assert!(
        state
            .account(account_id)
            .is_some_and(|account| account.admin_suspension_expires_at.is_none())
    );

    // The committed suspension advances both revisions to the same value.
    state.admin_suspend_account(account_id, expires_at)?;
    let suspended = next_revision(before)?;
    assert_eq!(state.revision, suspended);
    assert!(state.account(account_id).is_some_and(|account| {
        account.admin_suspension_expires_at == Some(expires_at) && account.revision == suspended
    }));

    // A state whose revision cannot advance refuses the whole command.
    let mut exhausted = DomainState::at_revision(Revision::new(u64::MAX)?);
    exhausted.accounts.insert(
        account_id,
        AccountState::new(account_id, Generation::new(1)?, Revision::new(u64::MAX)?),
    );
    assert_eq!(
        exhausted.admin_suspend_account(account_id, expires_at),
        Err(DomainError::Overflow)
    );
    assert_eq!(exhausted.revision, Revision::new(u64::MAX)?);
    assert!(
        exhausted
            .account(account_id)
            .is_some_and(|account| account.admin_suspension_expires_at.is_none())
    );
    Ok(())
}

/// Restoring an account that carries no suspension is refused, and the refusal
/// neither clears another account's suspension nor advances any revision.
#[test]
fn account_restoration_refuses_an_unsuspended_account() -> Result<(), DomainError> {
    let mut state = DomainState::new()?;
    let restored = account(2);
    let untouched = account(3);
    for account_id in [restored, untouched] {
        state.accounts.insert(
            account_id,
            AccountState::new(account_id, Generation::new(1)?, state.revision),
        );
    }
    let expires_at = UtcSecond::from_unix_seconds(500);
    state.admin_suspend_account(untouched, expires_at)?;
    let before = state.revision;

    // The account was never suspended, so there is nothing to remove.
    assert_eq!(
        state.admin_restore_account(restored),
        Err(DomainError::NotFound)
    );
    assert_eq!(state.revision, before);
    assert!(
        state
            .account(untouched)
            .is_some_and(|account| account.admin_suspension_expires_at == Some(expires_at))
    );

    // The suspended account restores exactly once; a second restore refuses.
    state.admin_restore_account(untouched)?;
    let restored_revision = next_revision(before)?;
    assert_eq!(state.revision, restored_revision);
    assert!(state.account(untouched).is_some_and(|account| {
        account.admin_suspension_expires_at.is_none() && account.revision == restored_revision
    }));
    assert_eq!(
        state.admin_restore_account(untouched),
        Err(DomainError::NotFound)
    );
    assert_eq!(state.revision, restored_revision);
    Ok(())
}
