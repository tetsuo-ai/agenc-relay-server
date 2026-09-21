//! Current schema3 grant contradictions must fail before mailbox publication.

#![forbid(unsafe_code)]

use super::*;
use agenc_relay_storage::StoredKey;

fn current_grant() -> TestResult<(Harness, [u8; 32])> {
    let (mut source, _, _) = finalization_fixture()?;
    let binding = source.binding_bytes()?;
    deliver_binding(&mut source, &binding)?;
    let token = fetch_token(&mut source)?;
    assert!(
        source.reloaded().is_ok(),
        "the exact original grant reconstructs"
    );
    Ok((source, token))
}

fn token_row(source: &Harness, token: [u8; 32]) -> TestResult<MailboxRow> {
    let expected = MailboxRow::token_key(&token)?;
    for write in &source.writes {
        let Write::Put {
            table: TableId::E2eeState,
            key,
            plaintext,
        } = write
        else {
            continue;
        };
        if *key == expected {
            let value = PersistentRecordValue::decode(TableId::E2eeState, plaintext)?;
            return Ok(MailboxRow::decode(value.body())?);
        }
    }
    Err("current token row".into())
}

fn put_row(source: &mut Harness, key: StoredKey, row: MailboxRow) -> TestResult {
    let write = crate::e2ee::coordinator::request::state_row(
        TableId::E2eeState,
        MAILBOX_ROW_KIND,
        key,
        row.encode()?,
    )
    .map_err(|code| format!("fixture row: {code:?}"))?;
    source.apply_logical_write(&write)
}

#[test]
fn mailbox_grant_reconstruction_refuses_another_valid_object_id() -> TestResult {
    let (mut source, token) = current_grant()?;
    let other = bind_other(&mut source)?;
    let mut row = token_row(&source, token)?;
    let MailboxRow::Token {
        object_id: stored, ..
    } = &mut row
    else {
        return Err("token".into());
    };
    assert_ne!(*stored, object_id(&other.bytes));
    *stored = object_id(&other.bytes);
    put_row(&mut source, MailboxRow::token_key(&token)?, row)?;
    assert!(
        source.reloaded().is_err(),
        "token ObjectId must agree with its Item"
    );
    Ok(())
}

#[test]
fn mailbox_grant_reconstruction_refuses_two_tokens_for_one_item() -> TestResult {
    let (mut source, token) = current_grant()?;
    let row = token_row(&source, token)?;
    let mut extra = token;
    *extra.first_mut().ok_or("token byte")? ^= 1;
    put_row(&mut source, MailboxRow::token_key(&extra)?, row)?;
    order_fixture_rows(&mut source);
    assert!(
        source.reloaded().is_err(),
        "key order cannot choose grant authority"
    );
    Ok(())
}

#[test]
fn mailbox_grant_reconstruction_refuses_a_contradictory_expiry() -> TestResult {
    let (mut source, token) = current_grant()?;
    let mut row = token_row(&source, token)?;
    let MailboxRow::Token { expires_at, .. } = &mut row else {
        return Err("token".into());
    };
    *expires_at = expires_at.checked_add(1).ok_or("expiry")?;
    put_row(&mut source, MailboxRow::token_key(&token)?, row)?;
    assert!(
        source.reloaded().is_err(),
        "the index cannot extend a grant's expiry"
    );
    Ok(())
}

#[test]
fn mailbox_grant_reconstruction_refuses_a_missing_current_token() -> TestResult {
    let (mut source, token) = current_grant()?;
    let delete = Write::delete(TableId::E2eeState, MailboxRow::token_key(&token)?)?;
    source.apply_logical_write(&delete)?;
    assert!(
        source.reloaded().is_err(),
        "a current Item grant needs its exact index"
    );
    Ok(())
}
