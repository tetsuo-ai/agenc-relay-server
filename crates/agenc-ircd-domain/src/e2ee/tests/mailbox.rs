#![forbid(unsafe_code)]

//! Device mailboxes.

use super::*;

const TARGET: Target = Target {
    account_digest: [1; 32],
    device_id: [2; 16],
};
const OTHER: Target = Target {
    account_digest: [1; 32],
    device_id: [3; 16],
};

fn tokens() -> impl FnMut() -> Id {
    let mut counter = 0_u8;
    move || {
        counter = counter.wrapping_add(1);
        [counter; 32]
    }
}

#[test]
fn items_are_fetched_with_session_bound_tokens_and_acknowledged_once() -> Result<(), MailboxError> {
    let mut mailboxes = Mailboxes::new();
    let mut next_token = tokens();
    assert_eq!(
        mailboxes.deliver(TARGET, MailboxKind::Welcome, [10; 32], [20; 32], 100, 1_000)?,
        0
    );
    assert_eq!(
        mailboxes.deliver(TARGET, MailboxKind::Welcome, [11; 32], [20; 32], 100, 1_000)?,
        1
    );
    assert_eq!(
        mailboxes.deliver(TARGET, MailboxKind::Binding, [12; 32], [0; 32], 100, 1_000)?,
        0,
        "sequences are per kind"
    );
    assert_eq!(mailboxes.queued(&TARGET, MailboxKind::Welcome), 2);
    assert!(mailboxes.references(&TARGET, &[20; 32]));
    assert!(!mailboxes.references(&OTHER, &[20; 32]));
    let page = mailboxes.fetch(TARGET, MailboxKind::Welcome, None, 1, 101, &mut next_token)?;
    assert_eq!(page.deliveries.len(), 2);
    assert_eq!(page.next, None);
    let first = page
        .deliveries
        .first()
        .copied()
        .ok_or(MailboxError::TokenInvalid)?;
    assert_eq!(first.token, [1; 32]);
    let again = mailboxes.fetch(TARGET, MailboxKind::Welcome, None, 1, 102, &mut next_token)?;
    assert_eq!(
        again.deliveries.first().map(|delivery| delivery.token),
        Some([1; 32]),
        "the same session keeps its token"
    );
    let other_session =
        mailboxes.fetch(TARGET, MailboxKind::Welcome, None, 2, 103, &mut next_token)?;
    let fresh = other_session
        .deliveries
        .first()
        .map(|delivery| delivery.token)
        .ok_or(MailboxError::TokenInvalid)?;
    assert_ne!(
        fresh, [1; 32],
        "a new session generation gets a fresh token"
    );
    assert_eq!(
        mailboxes.acknowledge(TARGET, [1; 32], [10; 32], 1, 104),
        Err(MailboxError::TokenInvalid),
        "the superseded token is gone"
    );
    assert_eq!(
        mailboxes.acknowledge(TARGET, fresh, [10; 32], 1, 104),
        Err(MailboxError::TokenInvalid),
        "wrong session generation"
    );
    assert_eq!(
        mailboxes.acknowledge(OTHER, fresh, [10; 32], 2, 104),
        Err(MailboxError::TokenInvalid),
        "another device cannot consume the token"
    );
    assert_eq!(
        mailboxes.acknowledge(TARGET, fresh, [11; 32], 2, 104),
        Err(MailboxError::ObjectMismatch)
    );
    assert_eq!(
        mailboxes.acknowledge(TARGET, fresh, [10; 32], 2, 104)?,
        AckOutcome::Acked
    );
    assert_eq!(
        mailboxes.acknowledge(TARGET, fresh, [10; 32], 2, 105)?,
        AckOutcome::Replayed
    );
    assert_eq!(
        mailboxes.acknowledge(TARGET, fresh, [11; 32], 2, 105),
        Err(MailboxError::ObjectMismatch)
    );
    assert_eq!(mailboxes.queued(&TARGET, MailboxKind::Welcome), 1);
    let expired = mailboxes.fetch(
        TARGET,
        MailboxKind::Welcome,
        None,
        2,
        103 + 601,
        &mut next_token,
    )?;
    assert_ne!(
        expired.deliveries.first().map(|delivery| delivery.token),
        other_session
            .deliveries
            .get(1)
            .map(|delivery| delivery.token),
        "an expired token is reissued"
    );
    mailboxes.expire(104 + 1_800);
    assert_eq!(
        mailboxes.acknowledge(TARGET, fresh, [10; 32], 2, 104 + 1_801),
        Err(MailboxError::TokenInvalid),
        "the acknowledgement result expired"
    );
    Ok(())
}

#[test]
fn pages_are_bounded_detach_invalidates_tokens_and_expiry_frees_items() -> Result<(), MailboxError>
{
    let mut mailboxes = Mailboxes::new();
    let mut next_token = tokens();
    for index in 0..40_u8 {
        mailboxes.deliver(
            TARGET,
            MailboxKind::Application,
            [index; 32],
            [5; 32],
            100,
            1_000,
        )?;
    }
    let page = mailboxes.fetch(
        TARGET,
        MailboxKind::Application,
        None,
        1,
        101,
        &mut next_token,
    )?;
    assert_eq!(page.deliveries.len(), 32);
    assert_eq!(page.next, Some(32));
    let rest = mailboxes.fetch(
        TARGET,
        MailboxKind::Application,
        page.next,
        1,
        101,
        &mut next_token,
    )?;
    assert_eq!(rest.deliveries.len(), 8);
    assert_eq!(rest.next, None);
    assert_eq!(mailboxes.detach(&TARGET), 40);
    assert_eq!(mailboxes.detach(&TARGET), 0);
    let token = page
        .deliveries
        .first()
        .map(|delivery| delivery.token)
        .ok_or(MailboxError::TokenInvalid)?;
    assert_eq!(
        mailboxes.acknowledge(TARGET, token, [0; 32], 1, 102),
        Err(MailboxError::TokenInvalid)
    );
    assert_eq!(mailboxes.queued(&TARGET, MailboxKind::Application), 40);
    let refetched = mailboxes.fetch(
        TARGET,
        MailboxKind::Application,
        None,
        1,
        102,
        &mut next_token,
    )?;
    assert_eq!(refetched.deliveries.len(), 32);
    let expired = mailboxes.expire(1_100);
    assert_eq!(expired.len(), 40);
    assert_eq!(mailboxes.queued(&TARGET, MailboxKind::Application), 0);
    let empty = mailboxes.fetch(
        TARGET,
        MailboxKind::Application,
        None,
        1,
        1_101,
        &mut next_token,
    )?;
    assert!(empty.deliveries.is_empty());
    assert!(!MailboxError::Overflow.to_string().is_empty());
    Ok(())
}
