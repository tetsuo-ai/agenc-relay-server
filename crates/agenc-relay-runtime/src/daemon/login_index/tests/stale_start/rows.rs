//! Exact restart-only transaction bodies are admitted through sealed reconstruction.
#![forbid(unsafe_code)]
#![cfg(test)]

use super::*;
use agenc_relay_auth::{
    AuthenticationTransactionRecord, CreationTransactionRecord, OPAQUE_SERVER_LOGIN_STATE_BYTES,
};
use agenc_relay_crypto::LoginIndexDigest;
use agenc_relay_storage::{
    LoginIndexStoredKey, LoginIndexValue, LoginIndexValueKind, RecordMutation, RecordReference,
};
use agenc_relay_types::AccountId;
use agenc_relay_types::{AccountRandomId, AccountServiceMessageKind, InviteId};

pub(super) const CREATION: TransactionId = TransactionId::from_bytes([14; 16]);
pub(super) const REJECTED: TransactionId = TransactionId::from_bytes([15; 16]);
pub(super) const AUTHENTICATION: TransactionId = TransactionId::from_bytes([16; 16]);
const DEADLINE: u64 = 900;

pub(super) fn owned_login() -> TestResult<StoredKey> {
    Ok(LoginIndexStoredKey::new(1, LoginIndexDigest::from_storage_key([30; 32]))?.encode()?)
}

pub(super) fn owned_invite() -> TestResult<StoredKey> {
    Ok(StoredKey::new(
        InviteId::from_bytes([17; 16]).as_bytes().to_vec(),
    )?)
}

pub(super) fn survivor_login() -> TestResult<StoredKey> {
    Ok(LoginIndexStoredKey::new(1, LoginIndexDigest::from_storage_key([31; 32]))?.encode()?)
}

pub(super) fn survivor_invite() -> TestResult<StoredKey> {
    Ok(StoredKey::new(
        InviteId::from_bytes([18; 16]).as_bytes().to_vec(),
    )?)
}

pub(super) fn records() -> TestResult<Vec<RecordMutation>> {
    let transaction_key = StoredKey::new(CREATION.as_bytes().to_vec())?;
    let invitation_key = owned_invite()?;
    let login_key = LoginIndexStoredKey::decode(owned_login()?.as_bytes())?;
    let deleted = AccountId::from_random(AccountRandomId::from_bytes([19; 16]));
    let account_key = KeyDeriver::account_key(deleted)?;
    let survivor_key = LoginIndexStoredKey::decode(survivor_login()?.as_bytes())?;
    Ok(vec![
        transaction(CREATION, true, Some(InviteId::from_bytes([17; 16])))?,
        put(
            TableId::LoginIndex,
            login_key.encode()?,
            LoginIndexValue::new(
                &login_key,
                LoginIndexValueKind::CreationReservation {
                    transaction_id: CREATION,
                    expires_at: DEADLINE,
                },
            )?
            .encode()?,
        )?,
        value(
            TableId::RegistrationInvite,
            invitation_key,
            1,
            Some(DEADLINE),
            vec![RecordReference::new(
                TableId::AuthTransaction,
                transaction_key,
            )?],
            Vec::new(),
        )?,
        transaction(REJECTED, false, None)?,
        authentication()?,
        value(
            TableId::Account,
            account_key.clone(),
            2,
            None,
            Vec::new(),
            Vec::new(),
        )?,
        put(
            TableId::LoginIndex,
            survivor_key.encode()?,
            LoginIndexValue::new(
                &survivor_key,
                LoginIndexValueKind::DeletionTombstone {
                    deleted_account_id: deleted,
                    expires_at: 3600,
                },
            )?
            .encode()?,
        )?,
        value(
            TableId::RegistrationInvite,
            survivor_invite()?,
            2,
            Some(3600),
            vec![RecordReference::new(TableId::Account, account_key)?],
            Vec::new(),
        )?,
    ])
}

fn put(table: TableId, key: StoredKey, body: Vec<u8>) -> TestResult<RecordMutation> {
    Ok(RecordMutation::put(table, key, 1, None, body)?)
}

fn value(
    table: TableId,
    key: StoredKey,
    kind: u16,
    expires: Option<u64>,
    references: Vec<RecordReference>,
    body: Vec<u8>,
) -> TestResult<RecordMutation> {
    put(
        table,
        key,
        PersistentRecordValue::new(table, kind, 1, 0, expires, references, body)?.encode()?,
    )
}

fn header(class: u16, transaction: TransactionId, message: AccountServiceMessageKind) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&1_u16.to_be_bytes());
    body.extend_from_slice(&class.to_be_bytes());
    body.extend_from_slice(transaction.as_bytes());
    body.extend_from_slice(&[1; 32]);
    body.extend_from_slice(&[21; 16]);
    body.extend_from_slice(&[22; 16]);
    body.extend_from_slice(&[23; 16]);
    body.extend_from_slice(&1_u64.to_be_bytes());
    body.extend_from_slice(&[24; 16]);
    body.extend_from_slice(&[25; 32]);
    body.extend_from_slice(&DEADLINE.to_be_bytes());
    body.extend_from_slice(&[1; 32]);
    body.extend_from_slice(&[26; 16]);
    body.extend_from_slice(&[27; 32]);
    body.extend_from_slice(&[28; 16]);
    body.extend_from_slice(&message.wire_value().to_be_bytes());
    body
}

fn transaction(
    id: TransactionId,
    admitted: bool,
    invitation: Option<InviteId>,
) -> TestResult<RecordMutation> {
    let mut body = header(1, id, AccountServiceMessageKind::AccountCreateStart);
    body.extend_from_slice(&(if admitted { 0_u16 } else { 8_u16 }).to_be_bytes());
    body.extend_from_slice(&[30; 32]);
    body.extend_from_slice(&[29; 32]);
    let references = match invitation {
        Some(invite) => {
            body.push(1);
            body.extend_from_slice(invite.as_bytes());
            // Invitation interval: not_before 3_000 < expires_at 3_600.
            body.extend_from_slice(&3_000_u64.to_be_bytes());
            body.extend_from_slice(&3600_u64.to_be_bytes());
            vec![RecordReference::new(
                TableId::RegistrationInvite,
                owned_invite()?,
            )?]
        }
        None => {
            body.push(0);
            body.extend_from_slice(&[0; 32]);
            Vec::new()
        }
    };
    let metadata = CreationTransactionRecord::parse(&body)?.into_restart_cleanup_metadata()?;
    assert_eq!(metadata.transaction_id(), id);
    assert_eq!(metadata.reservation_login_digest().is_some(), admitted);
    value(
        TableId::AuthTransaction,
        StoredKey::new(id.as_bytes().to_vec())?,
        1,
        Some(DEADLINE),
        references,
        body,
    )
}

fn authentication() -> TestResult<RecordMutation> {
    let mut body = header(
        2,
        AUTHENTICATION,
        AccountServiceMessageKind::OpaqueAuthStart,
    );
    body.push(2);
    body.extend_from_slice(&[0; 40]);
    body.extend_from_slice(&[29; 32]);
    body.extend_from_slice(&[0; OPAQUE_SERVER_LOGIN_STATE_BYTES]);
    let _checked = AuthenticationTransactionRecord::parse(&body)?;
    value(
        TableId::AuthTransaction,
        StoredKey::new(AUTHENTICATION.as_bytes().to_vec())?,
        2,
        Some(DEADLINE),
        Vec::new(),
        body,
    )
}
