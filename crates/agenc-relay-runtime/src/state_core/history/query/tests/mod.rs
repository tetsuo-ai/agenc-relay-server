//! Current account authority and bounded query ownership regressions.
#![forbid(unsafe_code)]

#[cfg(feature = "history")]
mod snapshot;

use super::*;
use crate::test_support::{StateCoreFixture, seed_account, seed_session};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn query_leases_are_bounded_and_never_wrap_when_released() -> TestResult {
    let counter = Arc::new(AtomicUsize::new(0));
    let mut leases = Vec::new();
    for _ in 0..MAX_QUERIES {
        leases.push(QueryLease::acquire(&counter)?);
    }
    assert!(QueryLease::acquire(&counter).is_err());
    assert_eq!(counter.load(Ordering::Acquire), MAX_QUERIES);
    drop(leases);
    assert_eq!(counter.load(Ordering::Acquire), 0);
    // An invalid internal lease cannot make the limiter wrap to usize::MAX.
    drop(QueryLease(Arc::clone(&counter)));
    assert_eq!(counter.load(Ordering::Acquire), 0);
    Ok(())
}

#[tokio::test]
async fn suspended_account_loses_history_authority_before_its_session_is_removed() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let context = fixture.context_mut()?;
    let account = seed_account(context, 20, 1)?;
    let identity = seed_session(context, 21, "HistoryOwner", Some(account))?;
    let session = context.domain.session(identity.user_id).ok_or("session")?;
    assert!(context.history_account(session)?.is_some());
    let expiry = context.utc_now()?.checked_add(60)?;
    context.domain.admin_suspend_account(account.0, expiry)?;
    let session = context
        .domain
        .session(identity.user_id)
        .ok_or("session still present")?;
    assert_eq!(session.account_session_generation(), account.1);
    assert!(context.history_account(session).is_err());
    context.domain.admin_restore_account(account.0)?;
    let session = context.domain.session(identity.user_id).ok_or("session")?;
    assert!(context.history_account(session)?.is_some());
    let guest = seed_session(context, 22, "HistoryGuest", None)?;
    assert!(
        context
            .history_account(context.domain.session(guest.user_id).ok_or("guest")?)?
            .is_none()
    );
    Ok(())
}
