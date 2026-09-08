//! Every obsolete row still needs its exact key, grammar, ordering, and scope.
#![forbid(unsafe_code)]

use super::*;
use agenc_ircd_storage::e2ee_records::DELIVERY_RECOVERY_ROW_KIND;
use agenc_ircd_storage::e2ee_records::delivery_recovery::DeliveryRecoveryRow;
use outbox::replay::ReplayLedgerRow;

pub(super) fn admit(
    job: &mut Job,
    truncated: bool,
    records: Vec<(StoredKey, PersistentRecordValue)>,
) -> Result<(), CompanionFault> {
    match job.phase {
        Phase::Owner => owner(job, truncated, records),
        Phase::Rows | Phase::Ranges => prefix(job, records),
        Phase::Done => Err(CompanionFault::Storage),
    }
}

fn owner(
    job: &mut Job,
    truncated: bool,
    records: Vec<(StoredKey, PersistentRecordValue)>,
) -> Result<(), CompanionFault> {
    if truncated || records.len() != 1 {
        return Err(CompanionFault::Storage);
    }
    let (key, value) = records.first().ok_or(CompanionFault::Storage)?;
    validate(value)?;
    let ReplayLedgerRow::Owner(owner) =
        ReplayLedgerRow::decode_at(key, value.body()).map_err(|_| CompanionFault::Storage)?
    else {
        return Err(CompanionFault::Storage);
    };
    if owner != job.candidate.replay.owner {
        return Err(CompanionFault::Storage);
    }
    job.phase = Phase::Rows;
    Ok(())
}

fn prefix(
    job: &mut Job,
    records: Vec<(StoredKey, PersistentRecordValue)>,
) -> Result<(), CompanionFault> {
    let mut previous = None;
    for (key, value) in records {
        validate(&value)?;
        let sequence = match job.phase {
            Phase::Rows => row(job, &key, &value)?,
            Phase::Ranges => range(job, &key, &value)?,
            _ => return Err(CompanionFault::Storage),
        };
        if previous.is_some_and(|previous| sequence <= previous) {
            return Err(CompanionFault::Storage);
        }
        previous = Some(sequence);
        if sequence < job.candidate.stamp.floor {
            job.deletes.push(key);
        }
    }
    job.phase = if job.phase == Phase::Rows && job.deletes.is_empty() {
        Phase::Ranges
    } else {
        Phase::Done
    };
    Ok(())
}

fn validate(value: &PersistentRecordValue) -> Result<(), CompanionFault> {
    if value.record_kind() != DELIVERY_RECOVERY_ROW_KIND || value.body().len() > 8_192 {
        return Err(CompanionFault::Storage);
    }
    Ok(())
}

fn row(job: &Job, key: &StoredKey, value: &PersistentRecordValue) -> Result<u64, CompanionFault> {
    let DeliveryRecoveryRow::Outbox(row) =
        DeliveryRecoveryRow::decode_at(key, value.body()).map_err(|_| CompanionFault::Storage)?
    else {
        return Err(CompanionFault::Storage);
    };
    let stamp = job.candidate.stamp;
    if row.scope() != &stamp.scope
        || row.generation() != stamp.generation
        || row.sequence() >= job.candidate.owner.cursor().next_sequence()
    {
        return Err(CompanionFault::Storage);
    }
    Ok(row.sequence())
}

fn range(job: &Job, key: &StoredKey, value: &PersistentRecordValue) -> Result<u64, CompanionFault> {
    let ReplayLedgerRow::Range(range) =
        ReplayLedgerRow::decode_at(key, value.body()).map_err(|_| CompanionFault::Storage)?
    else {
        return Err(CompanionFault::Storage);
    };
    let stamp = job.candidate.stamp;
    if range.scope() != &stamp.scope
        || range.generation() != stamp.generation
        || range.last() > job.candidate.replay.owner.fields().through
    {
        return Err(CompanionFault::Storage);
    }
    Ok(range.last())
}
