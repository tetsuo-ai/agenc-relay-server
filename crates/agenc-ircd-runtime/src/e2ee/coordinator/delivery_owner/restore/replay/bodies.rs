//! Every reference must resolve to its exact bounded body, even outside the hot cache.
#![forbid(unsafe_code)]

use super::*;
use agenc_ircd_storage::e2ee_records::{OBJECT_RECORD_KIND, ObjectRow};
use std::collections::BTreeMap;

pub(super) fn expected(rows: &[ScopedOutbox]) -> Result<BTreeMap<[u8; 32], u32>, CompanionFault> {
    if rows.is_empty() || rows.len() > BODY_ROWS {
        return Err(CompanionFault::Storage);
    }
    let mut objects = BTreeMap::new();
    for row in rows {
        insert(&mut objects, row.event_object_id(), row.event_bytes())?;
        if let Some(id) = row.payload_object_id() {
            insert(&mut objects, id, row.payload_bytes())?;
        }
    }
    Ok(objects)
}

fn insert(
    objects: &mut BTreeMap<[u8; 32], u32>,
    id: [u8; 32],
    bytes: u32,
) -> Result<(), CompanionFault> {
    if objects
        .insert(id, bytes)
        .is_some_and(|previous| previous != bytes)
    {
        return Err(CompanionFault::Storage);
    }
    Ok(())
}

pub(super) fn admit(
    job: &mut Job,
    truncated: bool,
    records: Vec<(StoredKey, PersistentRecordValue)>,
) -> Result<(), CompanionFault> {
    let expected = expected(&job.buffered)?;
    if truncated || records.len() != expected.len() {
        return Err(CompanionFault::Storage);
    }
    let mut objects = BTreeMap::new();
    for (key, value) in records {
        let id: [u8; 32] = key
            .as_bytes()
            .try_into()
            .map_err(|_| CompanionFault::Storage)?;
        let length = *expected.get(&id).ok_or(CompanionFault::Storage)?;
        if value.record_kind() != OBJECT_RECORD_KIND
            || value.body().len() as u64 > u64::from(length) + 8_192
        {
            return Err(CompanionFault::Storage);
        }
        let row = ObjectRow::decode(value.body()).map_err(|_| CompanionFault::Storage)?;
        if row.key().map_err(|_| CompanionFault::Storage)? != key
            || row.bytes.len() as u64 != u64::from(length)
            || objects.insert(id, row.bytes).is_some()
        {
            return Err(CompanionFault::Storage);
        }
    }
    for row in std::mem::take(&mut job.buffered) {
        let restored = super::super::decode_row(
            &objects,
            &job.owner,
            row.sequence(),
            row,
            job.gate.as_ref(),
            &job.backing,
        )?;
        job.verified = job.verified.checked_add(1).ok_or(CompanionFault::Storage)?;
        retain(job, restored)?;
    }
    job.bytes = 0;
    Ok(())
}

fn retain(job: &mut Job, row: super::super::StreamRow) -> Result<(), CompanionFault> {
    if row.acked() {
        let bytes = row_bytes(&row)?;
        job.hot_bytes = job
            .hot_bytes
            .checked_add(bytes)
            .ok_or(CompanionFault::Storage)?;
        // Make room before pushing, so the pre-reserved queue never grows.
        while job.stream.rows.len() >= MAX_ACKED_REPLAY_ROWS
            || job.hot_bytes > MAX_ACKED_CACHE_BYTES
        {
            let old = job.stream.rows.pop_front().ok_or(CompanionFault::Storage)?;
            if !old.acked() {
                return Err(CompanionFault::Storage);
            }
            job.hot_bytes = job
                .hot_bytes
                .checked_sub(row_bytes(&old)?)
                .ok_or(CompanionFault::Storage)?;
        }
    }
    if job.stream.rows.len() >= job.stream.rows.capacity() {
        return Err(CompanionFault::Storage);
    }
    job.stream.rows.push_back(row);
    Ok(())
}

fn row_bytes(row: &super::super::StreamRow) -> Result<u64, CompanionFault> {
    row.event
        .len()
        .checked_add(row.payload.as_ref().map_or(0, |(_, bytes)| bytes.len()))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(CompanionFault::Storage)
}
