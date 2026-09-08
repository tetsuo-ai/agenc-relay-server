#![forbid(unsafe_code)]

//! Device mailboxes.

#[path = "mailbox/expiry.rs"]
mod expiry;

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

#[test]
fn mailbox_admission_precedes_grants_and_preserves_filtered_items() -> Result<(), MailboxError> {
    let mut mailboxes = Mailboxes::new();
    for sequence in 0..36_u8 {
        let conversation = if sequence < 2 { [20; 32] } else { [21; 32] };
        mailboxes.deliver(
            TARGET,
            MailboxKind::Welcome,
            [sequence; 32],
            conversation,
            100,
            1_000,
        )?;
    }
    let next_sequences = mailboxes.next_sequence.clone();
    let mut calls = 0_usize;
    let mut tokens = || {
        calls += 1;
        [u8::try_from(calls).unwrap_or_default(); 32]
    };
    let selector = FetchSelector {
        target: TARGET,
        kind: MailboxKind::Welcome,
        cursor: None,
    };
    let page = mailboxes.fetch_admitted(selector, 7, 101, &mut tokens, &mut |item| {
        Ok(item.conversation_id != [20; 32])
    })?;
    assert_eq!(calls, MAX_BATCH_OBJECTS);
    assert_eq!(page.deliveries.len(), MAX_BATCH_OBJECTS);
    assert_eq!(page.deliveries.first().map(|item| item.sequence), Some(2));
    assert_eq!(page.next, Some(34));
    assert_eq!(mailboxes.items.len(), 36);
    assert_eq!(mailboxes.next_sequence, next_sequences);
    for sequence in 0..2 {
        let item = mailboxes
            .items
            .get(&ItemKey {
                target: TARGET,
                kind: MailboxKind::Welcome,
                sequence,
            })
            .ok_or(MailboxError::TokenInvalid)?;
        assert!(item.grant.is_none());
    }
    let mut next_token = 99_u8;
    let rest = mailboxes.fetch_admitted(
        FetchSelector {
            cursor: page.next,
            ..selector
        },
        7,
        101,
        &mut || {
            next_token = next_token.saturating_add(1);
            [next_token; 32]
        },
        &mut |_| Ok(true),
    )?;
    assert_eq!(rest.deliveries.len(), 2);
    assert_eq!(rest.next, None);
    Ok(())
}

#[test]
fn a_failed_item_admission_cannot_issue_an_earlier_items_grant() -> Result<(), MailboxError> {
    let mut mailboxes = Mailboxes::new();
    for id in [10, 11] {
        mailboxes.deliver(TARGET, MailboxKind::Welcome, [id; 32], [20; 32], 100, 1_000)?;
    }
    let before = mailboxes.items.clone();
    let mut calls = 0;
    let result = mailboxes.fetch_admitted(
        FetchSelector {
            target: TARGET,
            kind: MailboxKind::Welcome,
            cursor: None,
        },
        1,
        101,
        &mut || {
            calls += 1;
            [1; 32]
        },
        &mut |item| {
            if item.object_id == [11; 32] {
                Err(MailboxError::AdmissionRefused)
            } else {
                Ok(true)
            }
        },
    );
    assert_eq!(result, Err(MailboxError::AdmissionRefused));
    assert_eq!(calls, 0);
    assert_eq!(mailboxes.items, before);
    assert!(mailboxes.tokens.is_empty());
    assert!(!MailboxError::AdmissionRefused.to_string().is_empty());
    Ok(())
}

#[test]
fn acknowledgement_lookup_is_read_only_and_distinguishes_replay_from_absence()
-> Result<(), MailboxError> {
    let mut mailboxes = Mailboxes::new();
    mailboxes.deliver(TARGET, MailboxKind::Welcome, [10; 32], [20; 32], 100, 1_000)?;
    let page = mailboxes.fetch(TARGET, MailboxKind::Welcome, None, 7, 101, &mut || [2; 32])?;
    let token = page
        .deliveries
        .first()
        .ok_or(MailboxError::TokenInvalid)?
        .token;
    let before = mailboxes.items.clone();
    let item = mailboxes
        .acknowledgement_item(TARGET, token, [10; 32], 7, 102)?
        .ok_or(MailboxError::TokenInvalid)?;
    assert_eq!(item.0, MailboxKind::Welcome);
    assert_eq!(item.1, 0);
    assert_eq!(item.2.conversation_id, [20; 32]);
    assert_eq!(mailboxes.items, before);
    assert!(mailboxes.acks.is_empty());
    assert_invalid_acknowledgement_lookups(&mailboxes, token)?;
    assert_eq!(
        mailboxes.acknowledge(TARGET, token, [10; 32], 7, 102)?,
        AckOutcome::Acked
    );
    assert_eq!(
        mailboxes.acknowledgement_item(TARGET, token, [10; 32], 7, 103)?,
        None
    );
    assert_eq!(
        mailboxes.acknowledgement_item(TARGET, [99; 32], [10; 32], 7, 103),
        Err(MailboxError::TokenInvalid)
    );
    assert_eq!(
        mailboxes.acknowledgement_item(TARGET, token, [11; 32], 7, 103),
        Err(MailboxError::ObjectMismatch)
    );
    Ok(())
}

#[test]
fn restored_sequence_owners_survive_empty_queues_and_refuse_exhaustion() -> Result<(), MailboxError>
{
    let mut mailboxes = Mailboxes::new();
    mailboxes.restore_sequence(TARGET, MailboxKind::Binding, 41)?;
    assert_eq!(
        mailboxes.deliver(TARGET, MailboxKind::Binding, [10; 32], [0; 32], 100, 1_000)?,
        41
    );
    mailboxes.fetch(TARGET, MailboxKind::Binding, None, 1, 101, &mut || [11; 32])?;
    mailboxes.acknowledge(TARGET, [11; 32], [10; 32], 1, 102)?;
    assert_eq!(mailboxes.item_count(), 0);
    mailboxes.expire(102 + MAILBOX_ACK_RETENTION_SECONDS);
    assert_eq!(
        mailboxes.deliver(TARGET, MailboxKind::Binding, [12; 32], [0; 32], 200, 1)?,
        42
    );
    mailboxes.expire(201);
    assert_eq!(mailboxes.item_count(), 0);
    assert_eq!(
        mailboxes.deliver(TARGET, MailboxKind::Binding, [13; 32], [0; 32], 202, 1)?,
        43
    );
    mailboxes.restore_sequence(TARGET, MailboxKind::Welcome, u64::MAX)?;
    assert_eq!(
        mailboxes.deliver(TARGET, MailboxKind::Welcome, [14; 32], [0; 32], 202, 1),
        Err(MailboxError::Overflow)
    );
    assert_eq!(mailboxes.queued(&TARGET, MailboxKind::Welcome), 0);
    Ok(())
}

#[test]
fn a_restored_sequence_owner_must_cover_every_item_without_lowering_the_floor()
-> Result<(), MailboxError> {
    let mut mailboxes = Mailboxes::new();
    let item = Item {
        object_id: [10; 32],
        conversation_id: [0; 32],
        inserted_at: 100,
        expires_at: 1_000,
        grant: None,
    };
    mailboxes.restore_item(TARGET, MailboxKind::Binding, 9, item);
    for invalid in [0, 9] {
        assert_eq!(
            mailboxes.restore_sequence(TARGET, MailboxKind::Binding, invalid),
            Err(MailboxError::AdmissionRefused)
        );
    }
    mailboxes.restore_sequence(TARGET, MailboxKind::Binding, 20)?;
    assert_eq!(
        mailboxes.restore_sequence(TARGET, MailboxKind::Binding, 19),
        Err(MailboxError::AdmissionRefused)
    );
    assert_eq!(
        mailboxes.deliver(TARGET, MailboxKind::Binding, [11; 32], [0; 32], 101, 1_000)?,
        20
    );
    mailboxes.restore_item(TARGET, MailboxKind::Welcome, u64::MAX, item);
    assert_eq!(
        mailboxes.restore_sequence(TARGET, MailboxKind::Welcome, u64::MAX),
        Err(MailboxError::AdmissionRefused)
    );
    Ok(())
}

fn assert_invalid_acknowledgement_lookups(
    mailboxes: &Mailboxes,
    token: Id,
) -> Result<(), MailboxError> {
    assert_eq!(
        mailboxes.acknowledgement_item(OTHER, token, [10; 32], 7, 102),
        Err(MailboxError::TokenInvalid)
    );
    assert_eq!(
        mailboxes.acknowledgement_item(TARGET, token, [10; 32], 8, 102),
        Err(MailboxError::TokenInvalid)
    );
    assert_eq!(
        mailboxes.acknowledgement_item(TARGET, token, [10; 32], 7, 701),
        Err(MailboxError::TokenInvalid)
    );
    assert_eq!(
        mailboxes.acknowledgement_item(TARGET, token, [11; 32], 7, 102),
        Err(MailboxError::ObjectMismatch)
    );
    let item = mailboxes
        .acknowledgement_item(TARGET, token, [10; 32], 7, 102)?
        .ok_or(MailboxError::TokenInvalid)?;
    assert_eq!(item.2.object_id, [10; 32]);
    Ok(())
}
