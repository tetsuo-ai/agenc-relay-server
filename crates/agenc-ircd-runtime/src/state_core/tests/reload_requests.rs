//! Reload requests are single-flight, fenced by quiescence, and an audited
//! reload keeps its barrier until the exact outcome it reserved is durable.
#![forbid(unsafe_code)]

use agenc_ircd_admin::AdminAuditPhase::{OutcomeFailure, OutcomeSuccess};
use agenc_ircd_types::TransactionId;

use super::support::{account_plan, audit_event, empty_fanout};
use super::*;
use crate::runtime_config::{
    AuditedReloadResult, AuditedReloadStart, ConfigRevision, PreparedReload, ReloadActivation,
    ReloadCoreRequest, ReloadOutcome, ReloadRejection, RuntimeConfigHandle,
};
use crate::state_core::{CorruptionCause, StateCore};
use crate::test_support::{golden_config, golden_parts, golden_snapshot};

const REHASH: &[u8] = b"REHASH :reload now";

struct Reloading {
    fixture: StateCoreFixture,
    handle: RuntimeConfigHandle,
}

fn reloading(entropy: Vec<u8>) -> TestResult<Reloading> {
    let mut fixture = StateCoreFixture::new(entropy)?;
    let handle = RuntimeConfigHandle::new(golden_snapshot("AgenC", None)?);
    let _port = fixture.install_reload_port(handle.clone())?;
    Ok(Reloading { fixture, handle })
}

/// A candidate that changes only the live message of the day.
fn renamed(handle: &RuntimeConfigHandle, motd: &str) -> TestResult<Box<PreparedReload>> {
    Ok(Box::new(PreparedReload::new(
        &handle.load(),
        golden_config()?,
        golden_parts("AgenC", Some(motd))?,
    )?))
}

fn live_motd(handle: &RuntimeConfigHandle) -> Option<String> {
    handle.load().motd_arc().map(|motd| motd.to_string())
}

fn signal(
    state: &mut StateCore,
    prepared: Box<PreparedReload>,
) -> (Option<StateCoreExit>, oneshot::Receiver<ReloadOutcome>) {
    let (reply, response) = oneshot::channel();
    let exit = state.step_reload_request(ReloadCoreRequest::ActivateSignal { prepared, reply });
    (exit, response)
}

fn audited(
    state: &mut StateCore,
    prepared: Box<PreparedReload>,
) -> TestResult<(Option<StateCoreExit>, oneshot::Receiver<AuditedReloadStart>)> {
    let (reply, response) = oneshot::channel();
    let exit = state.step_reload_request(ReloadCoreRequest::ActivateAudited {
        prepared,
        success_event: Box::new(audit_event(OutcomeSuccess, REHASH)?),
        failure_event: Box::new(audit_event(OutcomeFailure, REHASH)?),
        reply,
    });
    Ok((exit, response))
}

fn commit(
    state: &mut StateCore,
    activation: ReloadActivation,
) -> (
    Option<StateCoreExit>,
    Option<Result<AuditedReloadResult, ReloadRejection>>,
) {
    let (reply, mut response) = oneshot::channel();
    let exit = state.step_reload_request(ReloadCoreRequest::CommitOutcome { activation, reply });
    (exit, response.try_recv().ok())
}

fn finalize(
    state: &mut StateCore,
    activation: ReloadActivation,
) -> Option<Result<ConfigRevision, ReloadRejection>> {
    let (reply, mut response) = oneshot::channel();
    let exit = state.step_reload_request(ReloadCoreRequest::Finalize { activation, reply });
    assert!(exit.is_none());
    response.try_recv().ok()
}

/// Starts an audited reload and returns its provisional activation.
fn provisional(
    state: &mut StateCore,
    prepared: Box<PreparedReload>,
) -> TestResult<ReloadActivation> {
    let (exit, mut response) = audited(state, prepared)?;
    if exit.is_some() || state.activate_pending_reload().is_some() {
        return Err("the audited reload ended the core".into());
    }
    match response.try_recv()? {
        AuditedReloadStart::Provisional(activation) => Ok(activation),
        other => Err(format!("not provisional: {other:?}").into()),
    }
}

#[test]
fn a_second_activation_is_busy_while_the_first_waits_for_its_safe_point() -> TestResult {
    let Reloading {
        mut fixture,
        handle,
    } = reloading(vec![9; 4096])?;
    let state = fixture.state_mut()?;
    let (exit, mut first) = signal(state, renamed(&handle, "First")?);
    assert!(exit.is_none());
    assert!(first.try_recv().is_err(), "the first activation is pending");
    let (exit, mut second) = signal(state, renamed(&handle, "Second")?);
    assert!(exit.is_none());
    assert_eq!(
        second.try_recv()?,
        ReloadOutcome::Rejected(ReloadRejection::Busy)
    );
    let (exit, mut third) = audited(state, renamed(&handle, "Third")?)?;
    assert!(exit.is_none());
    assert_eq!(
        third.try_recv()?,
        AuditedReloadStart::Refused(ReloadRejection::Busy)
    );
    assert!(state.activate_pending_reload().is_none());
    assert!(matches!(first.try_recv()?, ReloadOutcome::Applied(_)));
    assert_eq!(live_motd(&handle).as_deref(), Some("First"));
    Ok(())
}

#[test]
fn an_audited_activation_is_refused_while_quiescing() -> TestResult {
    let Reloading {
        mut fixture,
        handle,
    } = reloading(vec![9; 4096])?;
    let state = fixture.state_mut()?;
    state.context.quiescing = true;
    let (exit, mut response) = audited(state, renamed(&handle, "Late")?)?;
    assert!(exit.is_none());
    assert_eq!(
        response.try_recv()?,
        AuditedReloadStart::Refused(ReloadRejection::Quiescing)
    );
    assert!(state.reload_pending.is_none());
    Ok(())
}

#[test]
fn an_activation_with_no_installed_reload_handle_ends_the_core() -> TestResult {
    let handle = RuntimeConfigHandle::new(golden_snapshot("AgenC", None)?);
    let mut fixture = StateCoreFixture::new(vec![9; 4096])?;
    let state = fixture.state_mut()?;
    let (_exit, mut response) = signal(state, renamed(&handle, "Orphan")?);
    assert!(matches!(
        state.activate_pending_reload(),
        Some(StateCoreExit::Corrupt(CorruptionCause::ApplyFailed))
    ));
    assert_eq!(
        response.try_recv()?,
        ReloadOutcome::Rejected(ReloadRejection::StorageUnavailable)
    );
    let (_exit, mut response) = audited(state, renamed(&handle, "Orphan")?)?;
    assert!(matches!(
        state.activate_pending_reload(),
        Some(StateCoreExit::Corrupt(CorruptionCause::ApplyFailed))
    ));
    assert_eq!(response.try_recv()?, AuditedReloadStart::Indeterminate);
    Ok(())
}

#[test]
fn a_candidate_below_the_committed_database_size_is_rejected_for_current_use() -> TestResult {
    let Reloading {
        mut fixture,
        handle,
    } = reloading(vec![9; 4096])?;
    let state = fixture.state_mut()?;
    // The committed database already exceeds the candidate's ceiling.
    state.context.head.logical_database_bytes = (1 << 30) + 1;
    let (_exit, mut response) = signal(state, renamed(&handle, "Shrunk")?);
    assert!(state.activate_pending_reload().is_none());
    assert_eq!(
        response.try_recv()?,
        ReloadOutcome::Rejected(ReloadRejection::CurrentUse)
    );
    assert_eq!(live_motd(&handle), None);
    Ok(())
}

#[test]
fn an_audited_reload_with_an_invalid_outcome_pair_ends_the_core() -> TestResult {
    let Reloading {
        mut fixture,
        handle,
    } = reloading(vec![9; 4096])?;
    let state = fixture.state_mut()?;
    let (reply, mut response) = oneshot::channel();
    let exit = state.step_reload_request(ReloadCoreRequest::ActivateAudited {
        prepared: renamed(&handle, "Forged")?,
        success_event: Box::new(audit_event(OutcomeFailure, REHASH)?),
        failure_event: Box::new(audit_event(OutcomeFailure, REHASH)?),
        reply,
    });
    assert!(exit.is_none());
    assert!(matches!(
        state.activate_pending_reload(),
        Some(StateCoreExit::Corrupt(CorruptionCause::ProjectionFailed))
    ));
    assert_eq!(response.try_recv()?, AuditedReloadStart::Indeterminate);
    assert!(state.reload_provisional.is_none());
    Ok(())
}

#[test]
fn an_audited_reload_without_transaction_entropy_ends_the_core() -> TestResult {
    let Reloading {
        mut fixture,
        handle,
    } = reloading(Vec::new())?;
    let state = fixture.state_mut()?;
    let (_exit, mut response) = audited(state, renamed(&handle, "Dry")?)?;
    assert!(matches!(
        state.activate_pending_reload(),
        Some(StateCoreExit::Corrupt(CorruptionCause::ProjectionFailed))
    ));
    assert_eq!(response.try_recv()?, AuditedReloadStart::Indeterminate);
    Ok(())
}

#[test]
fn a_stale_audited_reload_reserves_its_failure_outcome_without_changing_live_state() -> TestResult {
    let Reloading {
        mut fixture,
        handle,
    } = reloading(vec![9; 4096])?;
    let state = fixture.state_mut()?;
    let stale = PreparedReload::new(
        &golden_snapshot("AgenC", None)?,
        golden_config()?,
        golden_parts("AgenC", Some("Stale"))?,
    )?;
    let (_exit, mut applied) = signal(state, renamed(&handle, "Current")?);
    assert!(state.activate_pending_reload().is_none());
    assert!(matches!(applied.try_recv()?, ReloadOutcome::Applied(_)));
    let activation = provisional(state, Box::new(stale))?;
    assert!(!activation.changes_live_state);
    assert_eq!(activation.revision, handle.load().revision());
    let (exit, answer) = commit(state, activation);
    assert!(exit.is_none());
    assert_eq!(answer, None, "the failure outcome waits for its receipt");
    assert!(state.admin_pending.is_some());
    assert_eq!(live_motd(&handle).as_deref(), Some("Current"));
    Ok(())
}

#[test]
fn a_provisional_reload_refuses_a_foreign_or_premature_commit_and_finalize() -> TestResult {
    let Reloading {
        mut fixture,
        handle,
    } = reloading(vec![9; 4096])?;
    let state = fixture.state_mut()?;
    let foreign = ReloadActivation {
        revision: ConfigRevision::INITIAL,
        transaction_id: TransactionId::from_bytes([0xEE; 16]),
        changes_live_state: false,
    };
    assert_eq!(
        commit(state, foreign).1,
        Some(Err(ReloadRejection::StaleRevision)),
        "nothing is provisional yet"
    );
    assert_eq!(
        finalize(state, foreign),
        Some(Err(ReloadRejection::StaleRevision))
    );
    let activation = provisional(state, renamed(&handle, "Audited")?)?;
    assert!(activation.changes_live_state);
    assert_eq!(
        commit(state, foreign).1,
        Some(Err(ReloadRejection::StaleRevision))
    );
    assert_eq!(
        finalize(state, foreign),
        Some(Err(ReloadRejection::StaleRevision))
    );
    assert_eq!(
        finalize(state, activation),
        Some(Err(ReloadRejection::Busy)),
        "the outcome is not durable yet"
    );
    assert_eq!(live_motd(&handle), None);
    assert!(state.reload_provisional.is_some());
    Ok(())
}

#[test]
fn a_reserved_outcome_is_committed_once_and_busy_while_storage_holds_it() -> TestResult {
    let Reloading {
        mut fixture,
        handle,
    } = reloading(vec![9; 4096])?;
    let state = fixture.state_mut()?;
    let activation = provisional(state, renamed(&handle, "Audited")?)?;
    let (exit, answer) = commit(state, activation);
    assert!(exit.is_none());
    assert_eq!(answer, None);
    assert_eq!(
        commit(state, activation).1,
        Some(Err(ReloadRejection::Busy)),
        "the first commit is still in flight"
    );
    assert_eq!(
        finalize(state, activation),
        Some(Err(ReloadRejection::Busy))
    );
    Ok(())
}

#[test]
fn a_reserved_outcome_is_busy_behind_a_gathering_client_batch() -> TestResult {
    let Reloading {
        mut fixture,
        handle,
    } = reloading(vec![9; 4096])?;
    let state = fixture.state_mut()?;
    let activation = provisional(state, renamed(&handle, "Audited")?)?;
    let plan = account_plan(&state.context, 7)?;
    state
        .context
        .stage_durable(plan, empty_fanout()?, None, 0)
        .map_err(|refused| format!("{refused:?}"))?;
    assert_eq!(
        commit(state, activation).1,
        Some(Err(ReloadRejection::Busy))
    );
    assert!(state.step_batch().is_none());
    assert!(
        !state.context.in_flight(),
        "a client batch never submits behind the reload barrier"
    );
    Ok(())
}
