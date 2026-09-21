//! Stale account authority is removed only through its typed reconstruction owner.
#![forbid(unsafe_code)]

use super::*;
use crate::account_service::recovered_transaction_cleanup;
use crate::state_core::durable::AccountServiceDurableWrite;

pub(super) fn cleanup_transactions(
    live: &mut LiveStorage,
    config: &Config,
) -> Result<(), LoginIndexRotationError> {
    let count = live
        .reconstruction
        .account_service
        .startup_transaction_cleanups()
        .len();
    for index in 0..count {
        let cleanup = live
            .reconstruction
            .account_service
            .startup_transaction_cleanups()
            .get(index)
            .ok_or(LoginIndexRotationError::Refused)?
            .clone();
        let writes = recovered_transaction_cleanup(cleanup)?.into_writes()?;
        commit_cleanup(live, config, &writes)?;
    }
    scan::scan_table_at(live, TableId::AuthTransaction, |_, _| {
        Err(LoginIndexRotationError::Refused)
    })
}

fn commit_cleanup(
    live: &mut LiveStorage,
    config: &Config,
    writes: &[AccountServiceDurableWrite],
) -> Result<(), LoginIndexRotationError> {
    let recovered = &mut live.reconstruction;
    let plan = recovered
        .domain
        .plan_account_service_checkpoint()
        .map_err(|_| LoginIndexRotationError::Refused)?;
    let transaction_id = startup_transaction_id()?;
    let projected = project_batch(
        transaction_id,
        &[PlanProjection {
            plan: &plan,
            response_count_increment: 0,
            account_service_writes: writes,
        }],
        &recovered.index,
        &live.keys,
        recovered.head,
        AccountingCeilings {
            database_max_bytes: config.storage.database_max_bytes,
            backup_max_bytes: config.storage.backup_max_bytes,
        },
        &mut OsEntropy,
    )?
    .ok_or(LoginIndexRotationError::Refused)?;
    let (batch, retained) = projected.into_parts();
    let expected_commit = recovered
        .head
        .storage_commit_sequence
        .checked_add(1)
        .ok_or(LoginIndexRotationError::Refused)?;
    let receipt = transaction::submit(&live.owner.port(), batch)?;
    if receipt.transaction_id != transaction_id
        || receipt.storage_commit_sequence != expected_commit
        || receipt.state_generation != plan.resulting_revision().get()
    {
        return Err(LoginIndexRotationError::Indeterminate);
    }
    recovered.head = retained.advance(&receipt);
    recovered.index.apply(retained.updates());
    refresh_startup_rows(
        &live.owner.port(),
        recovered,
        receipt.storage_commit_sequence,
    )
    .map_err(|_| LoginIndexRotationError::Indeterminate)?;
    let prepared = recovered
        .domain
        .prepare_mutation(plan)
        .map_err(|_| LoginIndexRotationError::Indeterminate)?;
    recovered
        .domain
        .apply_prepared(prepared)
        .map_err(|_| LoginIndexRotationError::Indeterminate)?;
    Ok(())
}
