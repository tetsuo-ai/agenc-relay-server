//! Every returned page binds its request, record grammar, ordering, and commit.
#![forbid(unsafe_code)]

use super::*;
use agenc_ircd_storage::e2ee_records::DELIVERY_RECOVERY_ROW_KIND;
use agenc_ircd_storage::e2ee_records::delivery_recovery::DeliveryRecoveryRow;
use agenc_ircd_storage::e2ee_records::delivery_recovery::outbox::replay::{
    ReplayLedgerRow, replay_owner_key,
};

pub(super) fn admit(
    reader: &mut Reader,
    query: &Query,
    commit: u64,
    truncated: bool,
    records: Vec<(StoredKey, PersistentRecordValue)>,
) -> Result<(), CompanionFault> {
    if reader.pending.as_ref() != Some(query)
        || records.len() > PAGE_ROWS as usize
        || (truncated && records.is_empty())
        || reader.pinned_commit.is_some_and(|pinned| pinned != commit)
    {
        return Err(CompanionFault::Storage);
    }
    reader.pinned_commit = Some(commit);
    match query.kind {
        Kind::Owner => owner(reader, query, truncated, records)?,
        Kind::Ranges(first) => ranges(reader, first, truncated, records)?,
        Kind::Rows(first) => rows(reader, first, truncated, records)?,
    }
    reader.pending = None;
    Ok(())
}

fn owner(
    reader: &mut Reader,
    query: &Query,
    truncated: bool,
    records: Vec<(StoredKey, PersistentRecordValue)>,
) -> Result<(), CompanionFault> {
    if truncated || records.len() > 1 || reader.scan.is_some() {
        return Err(CompanionFault::Storage);
    }
    let mut records = records.into_iter();
    let owner = records
        .next()
        .map(|(key, value)| decode_owner(query, &key, &value))
        .transpose()?;
    if reader
        .expected_owner
        .is_some_and(|expected| expected != owner)
    {
        return Err(CompanionFault::Storage);
    }
    reader.scan = Some(if let Some(owner) = owner {
        let inventory = Inventory::new(reader.current.clone(), owner)?;
        reader.next_row = owner.fields().first_retained;
        reader.next_range = owner.fields().first_retained;
        Scan::Ledger(Box::new(inventory))
    } else {
        Scan::Legacy(Box::new(legacy::Scan::new(reader.current.clone())))
    });
    Ok(())
}

fn decode_owner(
    query: &Query,
    key: &StoredKey,
    value: &PersistentRecordValue,
) -> Result<ReplayOwner, CompanionFault> {
    if *key
        != replay_owner_key(&query.scope, query.generation).map_err(|_| CompanionFault::Storage)?
    {
        return Err(CompanionFault::Storage);
    }
    let ReplayLedgerRow::Owner(owner) = ledger(key, value)? else {
        return Err(CompanionFault::Storage);
    };
    Ok(owner)
}

fn ranges(
    reader: &mut Reader,
    mut first: u64,
    truncated: bool,
    records: Vec<(StoredKey, PersistentRecordValue)>,
) -> Result<(), CompanionFault> {
    if !reader.ranges.is_empty() {
        return Err(CompanionFault::Storage);
    }
    for (key, value) in records {
        let ReplayLedgerRow::Range(range) = ledger(&key, &value)? else {
            return Err(CompanionFault::Storage);
        };
        let Some(Scan::Ledger(inventory)) = &reader.scan else {
            return Err(CompanionFault::Storage);
        };
        if range.scope() != reader.current.scope()
            || range.generation() != reader.current.cursor().generation()
            || range.last() < first
            || range.last() > inventory.owner().fields().through
        {
            return Err(CompanionFault::Storage);
        }
        first = range.last().checked_add(1).ok_or(CompanionFault::Storage)?;
        reader.ranges.push_back(range);
    }
    reader.next_range = first;
    reader.ranges_started = true;
    reader.ranges_done = !truncated;
    Ok(())
}

fn rows(
    reader: &mut Reader,
    mut first: u64,
    truncated: bool,
    records: Vec<(StoredKey, PersistentRecordValue)>,
) -> Result<(), CompanionFault> {
    if !reader.rows.is_empty() {
        return Err(CompanionFault::Storage);
    }
    for (key, value) in records {
        if value.record_kind() != DELIVERY_RECOVERY_ROW_KIND || value.body().len() > 8_192 {
            return Err(CompanionFault::Storage);
        }
        let DeliveryRecoveryRow::Outbox(row) = DeliveryRecoveryRow::decode_at(&key, value.body())
            .map_err(|_| CompanionFault::Storage)?
        else {
            return Err(CompanionFault::Storage);
        };
        if row.scope() != reader.current.scope()
            || row.generation() != reader.current.cursor().generation()
            || row.sequence() < first
        {
            return Err(CompanionFault::Storage);
        }
        first = row
            .sequence()
            .checked_add(1)
            .ok_or(CompanionFault::Storage)?;
        reader.rows.push_back(row);
    }
    reader.next_row = first;
    reader.rows_done = !truncated;
    Ok(())
}

fn ledger(
    key: &StoredKey,
    value: &PersistentRecordValue,
) -> Result<ReplayLedgerRow, CompanionFault> {
    if value.record_kind() != DELIVERY_RECOVERY_ROW_KIND {
        return Err(CompanionFault::Storage);
    }
    ReplayLedgerRow::decode_at(key, value.body()).map_err(|_| CompanionFault::Storage)
}
