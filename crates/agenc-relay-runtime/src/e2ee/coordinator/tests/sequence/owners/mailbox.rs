//! Account-wide charges follow durable item rows through refusal, restore, delivery grants and expiry.
#![forbid(unsafe_code)]
use super::*;
use agenc_relay_storage::e2ee_records::MailboxKind;

fn key(target: u8, device: u8, kind: MailboxKind, sequence: u64) -> TestResult<StoredKey> {
    Ok(MailboxRow::item_key(
        &[target; 32],
        &[device; 16],
        kind,
        sequence,
    )?)
}

fn item(k: StoredKey, bytes: &[u8]) -> TestResult<Write> {
    row(
        MAILBOX_ROW_KIND,
        k,
        MailboxRow::Item {
            object_id: object_id(bytes),
            conversation_id: CONVERSATION,
            inserted_at: NOW,
            expires_at: NOW + 3600,
            grant: None,
        }
        .encode()?,
    )
}

#[test]
fn device_and_kind_share_the_configured_account_budget_and_retire_only_after_commit() -> TestResult
{
    let mut coordinator = coordinator();
    let app = object(Kind::ApplicationMls, 11, 89)?;
    let welcome = object(Kind::WelcomeMls, 12, 97)?;
    let limit = u64::try_from(app.len() + welcome.len())?;
    coordinator.set_mailbox_bytes_per_account(limit);
    let mut writes = vec![
        object_write(&app)?,
        object_write(&welcome)?,
        item(key(1, 1, MailboxKind::Application, 0)?, &app)?,
        item(key(1, 2, MailboxKind::Welcome, 0)?, &welcome)?,
        item(key(2, 1, MailboxKind::Application, 0)?, &app)?,
    ];
    let staged = coordinator
        .stage_owners(&mut writes, NOW, false, STATE_GENERATION)
        .map_err(code)?;
    staged.apply(&mut coordinator.state);
    // Restoring the existing authoritative owner rows gives the same independent account charges.
    let rebuild = rebuild_from(&writes.iter().collect::<Vec<_>>())?;
    let mut restored = super::coordinator();
    rebuild.finish(&mut restored.state);
    assert_eq!(coordinator.state.owners, restored.state.owners);
    restored.set_mailbox_bytes_per_account(limit);
    for mut current in [coordinator, restored] {
        let extra = item(key(1, 3, MailboxKind::Application, 0)?, &app)?;
        assert_eq!(
            admit(&mut current, vec![extra], false)?,
            Err(E2eeReplyCode::RateLimited)
        );
        // Lowering the ceiling after restart must still permit the same item to be
        // rewritten for a grant and must permit ACK/expiry to delete its actual key.
        current.set_mailbox_bytes_per_account(1);
        assert!(
            admit(
                &mut current,
                vec![item(key(1, 2, MailboxKind::Welcome, 0)?, &welcome)?],
                false
            )?
            .is_ok()
        );
        assert!(
            admit(
                &mut current,
                vec![delete(key(1, 2, MailboxKind::Welcome, 0)?)?],
                false
            )?
            .is_ok()
        );
        current.set_mailbox_bytes_per_account(limit);
        assert!(
            admit(
                &mut current,
                vec![item(key(1, 3, MailboxKind::Application, 0)?, &app)?],
                false
            )?
            .is_ok()
        );
        assert_eq!(
            admit(
                &mut current,
                vec![item(key(1, 4, MailboxKind::Application, 0)?, &app)?],
                false
            )?,
            Err(E2eeReplyCode::RateLimited)
        );
    }
    Ok(())
}
