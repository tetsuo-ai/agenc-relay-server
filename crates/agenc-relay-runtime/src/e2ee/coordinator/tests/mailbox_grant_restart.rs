//! Normal attachment renewal must not restore a superseded delivery grant.

#![forbid(unsafe_code)]

use agenc_relay_storage::e2ee_records::{MAILBOX_ROW_KIND, MailboxRow};

use super::*;

#[path = "mailbox_grant_reconstruction.rs"]
mod contradictions;

fn fetch_token(source: &mut Harness) -> TestResult<[u8; 32]> {
    let page = ok(source.run(Op::FetchMailbox, &[2, 0], None)?)?;
    assert_eq!(page.responses.len(), 1);
    page.responses
        .first()
        .and_then(|row| row.delivery_token)
        .ok_or_else(|| "token".into())
}

fn retained_token_generations(source: &Harness) -> TestResult<Vec<u64>> {
    let mut generations = Vec::new();
    for write in &source.writes {
        let Write::Put {
            table: TableId::E2eeState,
            plaintext,
            ..
        } = write
        else {
            continue;
        };
        let value = PersistentRecordValue::decode(TableId::E2eeState, plaintext)?;
        if value.record_kind() != MAILBOX_ROW_KIND {
            continue;
        }
        if let MailboxRow::Token {
            session_generation, ..
        } = MailboxRow::decode(value.body())?
        {
            generations.push(session_generation);
        }
    }
    generations.sort_unstable();
    Ok(generations)
}

/// Storage's prefix scans return each table's exact logical keys in order.
fn order_fixture_rows(source: &mut Harness) {
    source
        .writes
        .sort_by(|left, right| stored_order_key(left).cmp(&stored_order_key(right)));
}

fn stored_order_key(row: &Write) -> (u16, &[u8]) {
    match row {
        Write::Put { table, key, .. } | Write::Delete { table, key } => {
            (table.as_u16(), key.as_bytes())
        }
    }
}

#[test]
fn restart_keeps_the_current_attachment_grant_when_stale_tokens_survive() -> TestResult {
    let (mut source, _, _) = finalization_fixture()?;
    let binding = source.binding_bytes()?;
    deliver_binding(&mut source, &binding)?;
    let original_generation = source.device().ok_or("attached device")?.1;
    source.entropy.0 = 128;
    let old = fetch_token(&mut source)?;
    let (current_generation, _) = source.attach()?;
    assert!(current_generation > original_generation);
    source.entropy.0 = 0;
    let current = fetch_token(&mut source)?;
    assert!(
        old > current,
        "the superseded key sorts after the current grant"
    );
    assert_eq!(
        retained_token_generations(&source)?,
        vec![current_generation]
    );
    let mut parameters = current.to_vec();
    parameters.extend_from_slice(&object_id(&binding));
    let positive = evaluate_request(&mut source, Op::AcknowledgeMailbox, &parameters, None)?
        .map_err(|fail| {
            format!(
                "live current grant refused before reconstruction: {:?}",
                fail.code
            )
        })?;
    assert_eq!(
        positive.result,
        ResultBody::MailboxAcked(current, object_id(&binding))
    );
    assert_eq!(positive.writes.len(), 3);
    order_fixture_rows(&mut source);
    let mut restored = source.reloaded()?;
    let accepted = evaluate_request(&mut restored, Op::AcknowledgeMailbox, &parameters, None)?
        .map_err(|fail| format!("post-reconstruction current grant refused: {:?}", fail.code))?;
    assert_eq!(
        accepted.result,
        ResultBody::MailboxAcked(current, object_id(&binding))
    );
    assert_eq!(accepted.writes.len(), 3);
    Ok(())
}
