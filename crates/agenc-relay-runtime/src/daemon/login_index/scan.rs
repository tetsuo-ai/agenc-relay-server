//! Full authenticated scans remain on the exact exclusive owner's current commit.
#![forbid(unsafe_code)]

use super::*;
use agenc_relay_crypto::LoginIndexKeyId;
use agenc_relay_storage::{
    LoginIndexStoredKey, LoginIndexTransitionPreflight, LoginIndexValue, LoginIndexValueKind,
    MAX_STORED_KEY_BYTES, ReadRecord, SealedRecord, StoredKey,
};

pub(super) fn scan_login_index(
    live: &LiveStorage,
    before: LoginIndexKeyState,
    new_key_id: Option<LoginIndexKeyId>,
) -> Result<LoginIndexKeyState, LoginIndexRotationError> {
    let mut start = new_key_id
        .map(|id| LoginIndexTransitionPreflight::new(before, id))
        .transpose()?;
    let finished = if start.is_none() {
        Some(before.finish()?)
    } else {
        None
    };
    scan_table_at(live, TableId::LoginIndex, |key, opened| {
        let key = LoginIndexStoredKey::decode(key.as_bytes())?;
        let value = LoginIndexValue::decode(opened, &key)?;
        match &mut start {
            Some(preflight) => preflight.observe(&key, &value)?,
            None => observe_finished_index(&key, &value, before)?,
        }
        Ok(())
    })?;
    match start {
        Some(preflight) => Ok(preflight.finish()?),
        None => finished.ok_or(LoginIndexRotationError::Refused),
    }
}

fn observe_finished_index(
    key: &LoginIndexStoredKey,
    value: &LoginIndexValue,
    before: LoginIndexKeyState,
) -> Result<(), LoginIndexRotationError> {
    if key.generation() != before.current_generation()
        || matches!(
            value.kind(),
            LoginIndexValueKind::CreationReservation { .. }
        )
    {
        return Err(LoginIndexRotationError::Refused);
    }
    Ok(())
}

pub(super) fn scan_table_at(
    live: &LiveStorage,
    table: TableId,
    mut visit: impl FnMut(&StoredKey, &[u8]) -> Result<(), LoginIndexRotationError>,
) -> Result<(), LoginIndexRotationError> {
    let end = StoredKey::new(vec![0xff; MAX_STORED_KEY_BYTES])?;
    let mut start = StoredKey::new(vec![0])?;
    let port = live.owner.port();
    loop {
        let result = port
            .try_read(ReadPlan::range(table, start.clone(), end.clone(), 256)?)?
            .wait()?;
        if result.storage_commit_sequence != live.reconstruction.head.storage_commit_sequence {
            return Err(LoginIndexRotationError::Refused);
        }
        let mut last = None;
        for record in &result.records {
            if record.table != table
                || record.key < start
                || record.key >= end
                || last
                    .as_ref()
                    .is_some_and(|previous| previous >= &record.key)
            {
                return Err(LoginIndexRotationError::Refused);
            }
            visit_opened(live, record, &mut visit)?;
            last = Some(record.key.clone());
        }
        if !result.truncated {
            return Ok(());
        }
        let mut bytes = last
            .ok_or(LoginIndexRotationError::Refused)?
            .as_bytes()
            .to_vec();
        bytes
            .try_reserve_exact(1)
            .map_err(|_| LoginIndexRotationError::Refused)?;
        bytes.push(0);
        start = StoredKey::new(bytes)?;
    }
}

fn visit_opened(
    live: &LiveStorage,
    record: &ReadRecord,
    visit: &mut impl FnMut(&StoredKey, &[u8]) -> Result<(), LoginIndexRotationError>,
) -> Result<(), LoginIndexRotationError> {
    let sealed = SealedRecord::decode(&record.sealed_record)?;
    let opened = live.keys.open(record.table, &record.key, &sealed)?;
    visit(&record.key, opened.expose_for_storage_codec())
}
