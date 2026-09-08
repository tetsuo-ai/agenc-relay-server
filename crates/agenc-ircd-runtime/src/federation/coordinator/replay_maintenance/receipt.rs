//! The exact maintenance transaction advances retention without changing the delivery cursor.
#![forbid(unsafe_code)]

use super::*;
use crate::budget::MemoryPermit;
use crate::state_core::fanout::FanoutRequest;
use crate::state_core::{StageAccepted, StageRefused};

pub(in super::super) struct Receipt {
    pub(in super::super) staged_after: u64,
    revision: u64,
    prepared: task::Prepared,
    _backing: MemoryPermit,
}

pub(super) fn stage(
    coordinator: &FederationCoordinator,
    context: &mut StateCoreContext,
    prepared: task::Prepared,
    commit: u64,
) -> Result<Receipt, CompanionFault> {
    if coordinator.pending.is_some()
        || context.in_flight()
        || context.pending_len() != 0
        || context.is_quiescing()
        || context.head().storage_commit_sequence != commit
    {
        return Err(CompanionFault::Protocol);
    }
    prepared.validate(
        coordinator
            .companion_exec
            .as_ref()
            .ok_or(CompanionFault::Storage)?,
    )?;
    let backing = context
        .reserve_output_backing(128 * (agenc_ircd_storage::MAX_STORED_KEY_BYTES + 128) + 8_192)
        .map_err(|_| CompanionFault::Ceiling)?;
    let plan = context
        .domain()
        .plan_account_service_checkpoint()
        .map_err(|_| CompanionFault::Storage)?;
    let revision = plan.resulting_revision().get();
    let writes = prepared
        .writes()?
        .into_iter()
        .map(|write| {
            write
                .at_revision(revision)
                .map_err(|_| CompanionFault::Storage)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let fanout = FanoutRequest::new(Vec::new(), Vec::new()).map_err(|_| CompanionFault::Storage)?;
    let accepted = context
        .stage_durable_with_account_service(plan, fanout, None, 0, writes)
        .map_err(|error| match error {
            StageRefused::Busy | StageRefused::Quiescing | StageRefused::Fanout(_) => {
                CompanionFault::Ceiling
            }
            StageRefused::Domain(_) => CompanionFault::Storage,
        })?;
    if !matches!(accepted, StageAccepted::Staged { .. }) {
        return Err(CompanionFault::Storage);
    }
    Ok(Receipt {
        staged_after: commit,
        revision,
        prepared,
        _backing: backing,
    })
}

pub(in super::super) fn committed(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    receipt: Receipt,
) {
    let matches = receipt.staged_after.checked_add(1)
        == Some(context.head().storage_commit_sequence)
        && receipt.revision == context.domain().revision().get();
    if !matches {
        super::super::startup::fail_restore(coordinator);
        return;
    }
    let applied = coordinator
        .companion_exec
        .as_mut()
        .ok_or(CompanionFault::Storage)
        .and_then(|executor| receipt.prepared.apply(executor));
    if applied.is_err() {
        super::super::startup::fail_restore(coordinator);
        return;
    }
    super::schedule(coordinator, context, RETRY_MILLIS);
}

pub(in super::super) fn rejected(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    _receipt: Receipt,
) {
    super::schedule(coordinator, context, RETRY_MILLIS);
}
