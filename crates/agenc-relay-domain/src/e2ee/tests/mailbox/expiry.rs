//! Admission respects stored expiry even before a maintenance transaction.
#![forbid(unsafe_code)]
use super::*;
use crate::e2ee::mailbox::expiry::{Cursor, MAX_EXPIRY_ENTRIES, Plan};

#[test]
fn a_full_live_page_does_not_skip_the_expired_item_after_its_cursor() -> Result<(), MailboxError> {
    let mut mailboxes = Mailboxes::new();
    for sequence in 0..=MAX_EXPIRY_ENTRIES {
        mailboxes.deliver(
            TARGET,
            MailboxKind::Application,
            [5; 32],
            [6; 32],
            1,
            if sequence == MAX_EXPIRY_ENTRIES {
                9
            } else {
                99
            },
        )?;
    }
    let first = Plan::capture(&mailboxes, Cursor::default(), 10);
    assert!(first.is_empty());
    assert!(!first.completes_cycle());
    let next = Plan::capture(&mailboxes, first.next_cursor(), 10);
    assert_eq!(next.changes().count(), 1);
    next.apply(&mut mailboxes)?;
    assert_eq!(mailboxes.item_count(), MAX_EXPIRY_ENTRIES);
    assert_eq!(
        mailboxes.deliver(TARGET, MailboxKind::Application, [5; 32], [6; 32], 10, 100)?,
        129
    );
    Ok(())
}

#[test]
fn ack_expiry_has_its_own_bounded_cursor_and_preserves_live_results() -> Result<(), MailboxError> {
    let mut mailboxes = Mailboxes::new();
    for index in 0..130_u8 {
        mailboxes.restore_ack(
            TARGET,
            [index; 32],
            [5; 32],
            if index == 129 { 100 } else { 10 },
        );
    }
    let empty = Plan::capture(&mailboxes, Cursor::default(), 10);
    let first = Plan::capture(&mailboxes, empty.next_cursor(), 10);
    assert_eq!(first.changes().count(), MAX_EXPIRY_ENTRIES);
    first.apply(&mut mailboxes)?;
    assert_eq!(mailboxes.acks.len(), 2);
    assert!(!first.completes_cycle());
    let rest = Plan::capture(&mailboxes, first.next_cursor(), 10);
    assert_eq!(rest.changes().count(), 1);
    assert!(rest.completes_cycle());
    rest.apply(&mut mailboxes)?;
    assert_eq!(mailboxes.acks.len(), 1);
    assert_eq!(
        mailboxes.acknowledge(TARGET, [129; 32], [5; 32], 1, 10)?,
        AckOutcome::Replayed
    );
    Ok(())
}

#[test]
fn a_changed_item_or_token_index_prevents_every_captured_mutation() -> Result<(), MailboxError> {
    for token_conflict in [false, true] {
        let mut mailboxes = Mailboxes::new();
        for sequence in 0..2 {
            mailboxes.restore_item(
                TARGET,
                MailboxKind::Welcome,
                sequence,
                Item {
                    object_id: [5; 32],
                    conversation_id: [6; 32],
                    inserted_at: 1,
                    expires_at: 10,
                    grant: Some(Grant {
                        token: [u8::try_from(sequence).map_err(|_| MailboxError::Overflow)?; 32],
                        session_generation: 7,
                        expires_at: 100,
                    }),
                },
            );
        }
        let plan = Plan::capture(&mailboxes, Cursor::default(), 10);
        let key = ItemKey {
            target: TARGET,
            kind: MailboxKind::Welcome,
            sequence: 1,
        };
        if token_conflict {
            mailboxes.tokens.insert(
                [1; 32],
                ItemKey {
                    target: OTHER,
                    ..key
                },
            );
        } else {
            mailboxes
                .items
                .get_mut(&key)
                .ok_or(MailboxError::TokenInvalid)?
                .expires_at = 100;
        }
        let before = mailboxes.items.clone();
        assert_eq!(
            plan.apply(&mut mailboxes),
            Err(MailboxError::AdmissionRefused)
        );
        assert_eq!(mailboxes.items, before);
        assert_eq!(mailboxes.item_count(), 2);
    }
    Ok(())
}

#[test]
fn changed_ack_identity_prevents_an_earlier_captured_ack_deletion() -> Result<(), MailboxError> {
    let mut mailboxes = Mailboxes::new();
    mailboxes.restore_ack(TARGET, [1; 32], [5; 32], 10);
    mailboxes.restore_ack(TARGET, [2; 32], [5; 32], 10);
    let empty = Plan::capture(&mailboxes, Cursor::default(), 10);
    let plan = Plan::capture(&mailboxes, empty.next_cursor(), 10);
    mailboxes.restore_ack(TARGET, [2; 32], [6; 32], 10);
    let before = mailboxes.acks.clone();
    assert_eq!(
        plan.apply(&mut mailboxes),
        Err(MailboxError::AdmissionRefused)
    );
    assert_eq!(mailboxes.acks, before);
    Ok(())
}

#[test]
fn expired_ack_result_is_invalid_before_cleanup() {
    let mut mailboxes = Mailboxes::new();
    mailboxes.restore_ack(TARGET, [4; 32], [5; 32], 1000);
    assert_eq!(
        mailboxes.acknowledge(TARGET, [4; 32], [5; 32], 1, 999),
        Ok(AckOutcome::Replayed)
    );
    assert_eq!(
        mailboxes.acknowledge(TARGET, [4; 32], [5; 32], 1, 1000),
        Err(MailboxError::TokenInvalid)
    );
    assert_eq!(mailboxes.acks.len(), 1);
}

#[test]
fn expired_item_is_invalid_while_its_grant_is_still_live() -> Result<(), MailboxError> {
    let mut mailboxes = Mailboxes::new();
    mailboxes.deliver(TARGET, MailboxKind::Application, [5; 32], [6; 32], 1, 999)?;
    mailboxes.fetch(TARGET, MailboxKind::Application, None, 1, 999, &mut || {
        [4; 32]
    })?;
    assert!(
        mailboxes
            .acknowledgement_item(TARGET, [4; 32], [5; 32], 1, 999)?
            .is_some()
    );
    assert_eq!(
        mailboxes.acknowledge(TARGET, [4; 32], [5; 32], 1, 1000),
        Err(MailboxError::TokenInvalid)
    );
    assert_eq!(mailboxes.item_count(), 1);
    Ok(())
}
