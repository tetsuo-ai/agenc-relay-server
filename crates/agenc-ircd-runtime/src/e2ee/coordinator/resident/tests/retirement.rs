//! Envelope-only retirement checks preserve control kinds and conservative reference guards.
#![forbid(unsafe_code)]
use super::*;
mod admission;
use agenc_ircd_domain::e2ee::mailbox::{Item, MailboxKind as DomainKind, Target};

#[test]
fn retirement_releases_each_payload_kind_but_keeps_commit_and_binding_objects() -> TestResult {
    for (kind, mailbox_kind) in [
        (Kind::ApplicationMls, MailboxKind::Application),
        (Kind::WelcomeMls, MailboxKind::Welcome),
        (Kind::StagedReinit, MailboxKind::StagedReinit),
    ] {
        let (budget, port) = pool(1 << 20);
        let (bytes, write) = object(kind, 1, 100)?;
        let mut state = CompanionState::default();
        let writes = vec![
            write,
            mailbox(&bytes, mailbox_kind, 1)?,
            object(Kind::CommitMls, 2, 100)?.1,
            object(Kind::ConversationBinding, 3, 100)?.1,
        ];
        admitted(&state, &writes, &port)?.apply(&mut state);
        let id = ObjectId::compute(&bytes);
        let before = budget.charged();
        let charge = state
            .object_memory
            .get(id.as_bytes())
            .ok_or("charge")?
            .bytes();
        retire_payload(&mut state, id.as_bytes());
        assert_eq!(state.objects.len(), 2);
        assert_eq!(state.object_memory.len(), 2);
        assert_eq!(budget.charged(), before - charge);
        let remaining: Vec<_> = state.objects.keys().copied().collect();
        for id in remaining {
            retire_payload(&mut state, &id);
        }
        assert_eq!(state.objects.len(), 2);
        drop(state);
        assert_eq!(budget.charged(), 0);
    }
    Ok(())
}

#[test]
fn another_targets_retained_item_blocks_retirement_even_after_its_expiry() -> TestResult {
    let (budget, port) = pool(1 << 20);
    let (bytes, write) = object(Kind::ApplicationMls, 1, 100)?;
    let id = *ObjectId::compute(&bytes).as_bytes();
    let mut state = CompanionState::default();
    admitted(
        &state,
        &[write, mailbox(&bytes, MailboxKind::Application, 1)?],
        &port,
    )?
    .apply(&mut state);
    state.mailboxes.restore_item(
        Target {
            account_digest: [99; 32],
            device_id: [99; 16],
        },
        DomainKind::Application,
        99,
        Item {
            object_id: id,
            conversation_id: [2; 32],
            inserted_at: 0,
            expires_at: 1,
            grant: None,
        },
    );
    let before = budget.charged();
    retire_payload(&mut state, &id);
    assert_eq!(state.objects.get(&id), Some(&bytes));
    assert_eq!(budget.charged(), before);
    Ok(())
}

#[test]
fn inconsistent_byte_accounting_keeps_the_body_and_its_reservation() -> TestResult {
    let (budget, port) = pool(1 << 20);
    let (bytes, write) = object(Kind::WelcomeMls, 1, 100)?;
    let id = *ObjectId::compute(&bytes).as_bytes();
    let mut state = CompanionState::default();
    admitted(
        &state,
        &[write, mailbox(&bytes, MailboxKind::Welcome, 1)?],
        &port,
    )?
    .apply(&mut state);
    let before = budget.charged();
    state.object_bytes = 0;
    retire_payload(&mut state, &id);
    assert_eq!(state.objects.get(&id), Some(&bytes));
    assert!(state.object_memory.contains_key(&id));
    assert_eq!(budget.charged(), before);
    Ok(())
}
