//! A reload candidate is measured against live use before it is published:
//! the response batch limit must be usable, live query snapshots and invites
//! must fit the candidate's ceilings, and an audited candidate that fails a
//! floor reserves its failure outcome and finalizes back to the old revision.
#![forbid(unsafe_code)]

use agenc_relay_admin::AdminAuditPhase::{OutcomeFailure, OutcomeSuccess};
use agenc_relay_config::LimitKey;
use agenc_relay_domain::{
    CanonicalCommand, ChannelNameValue, ChannelTarget, NicknameValue, OperationalLimits,
    PlanDecision,
};

use super::support::{audit_event, storage_owner_idle};
use super::*;
use crate::runtime_config::{
    AuditedReloadResult, AuditedReloadStart, PreparedReload, ReloadActivation, ReloadCoreRequest,
    ReloadOutcome, ReloadRejection, RuntimeConfigHandle,
};
use crate::state_core::StateCoreContext;
use crate::state_core::{CompletionStep, StateCore};
use crate::test_support::{
    answer_external, apply_live_plan, bind_live_session, golden_config, golden_parts,
    golden_snapshot, negotiated_capabilities, plan_live, seed_session,
};
use agenc_relay_testkit::DomainTestIdentity;

const REHASH: &[u8] = b"REHASH :reload now";

fn reloading() -> TestResult<(StateCoreFixture, RuntimeConfigHandle)> {
    let mut fixture = StateCoreFixture::new(vec![9; 4096])?;
    let handle = RuntimeConfigHandle::new(golden_snapshot("AgenC", None)?);
    let _port = fixture.install_reload_port(handle.clone())?;
    Ok((fixture, handle))
}

fn signal(state: &mut StateCore, prepared: PreparedReload) -> TestResult<ReloadOutcome> {
    let (reply, mut response) = oneshot::channel();
    let exit = state.step_reload_request(ReloadCoreRequest::ActivateSignal {
        prepared: Box::new(prepared),
        reply,
    });
    assert!(exit.is_none());
    assert!(state.activate_pending_reload().is_none());
    Ok(response.try_recv()?)
}

fn with_limit(key: LimitKey, value: u64) -> TestResult<agenc_relay_config::Config> {
    let mut config = golden_config()?;
    config.limits.values = config.limits.values.with(key, value);
    Ok(config)
}

#[test]
fn a_candidate_with_an_unusable_response_batch_limit_is_rejected_for_current_use() -> TestResult {
    let (mut fixture, handle) = reloading()?;
    let state = fixture.state_mut()?;
    for value in [0, 262_145] {
        let prepared = PreparedReload::new(
            &handle.load(),
            with_limit(LimitKey::ResponseBatchBytes, value)?,
            golden_parts("AgenC", Some("Batchless"))?,
        )?;
        assert_eq!(
            signal(state, prepared)?,
            ReloadOutcome::Rejected(ReloadRejection::CurrentUse),
            "response_batch_bytes = {value}"
        );
    }
    assert_eq!(handle.load().motd_arc(), None);
    Ok(())
}

#[test]
fn a_candidate_below_a_live_query_snapshot_is_rejected_for_current_use() -> TestResult {
    let (mut fixture, handle) = reloading()?;
    let context = fixture.context_mut()?;
    let viewer = seed_session(context, 1, "Viewer", None)?;
    let _sink = bind_live_session(context, 1, viewer, negotiated_capabilities(&[])?, true)?;
    context
        .sessions_mut()
        .begin_active_query(ConnectionGeneration::new(1), 20_000, 4_096)?;
    let state = fixture.state_mut()?;
    let prepared = PreparedReload::new(
        &handle.load(),
        golden_config()?,
        golden_parts("AgenC", Some("Queried"))?,
    )?;
    assert_eq!(
        signal(state, prepared)?,
        ReloadOutcome::Rejected(ReloadRejection::CurrentUse),
        "the live snapshot holds more rows than the golden ceiling"
    );
    state
        .context
        .sessions_mut()
        .end_active_query(ConnectionGeneration::new(1));
    let prepared = PreparedReload::new(
        &handle.load(),
        golden_config()?,
        golden_parts("AgenC", Some("Queried"))?,
    )?;
    assert!(matches!(
        signal(state, prepared)?,
        ReloadOutcome::Applied(_)
    ));
    assert_eq!(
        handle
            .load()
            .motd_arc()
            .map(|motd| motd.to_string())
            .as_deref(),
        Some("Queried")
    );
    Ok(())
}

/// Plans one invite with a distinct invite identity per `seed`; the shared
/// answerer would hand every invite the same identity.
fn plan_invite(
    context: &StateCoreContext,
    identity: DomainTestIdentity,
    command: &dyn Fn() -> Result<CanonicalCommand, agenc_relay_domain::DomainError>,
    seed: u8,
) -> TestResult<agenc_relay_domain::MutationPlan> {
    use agenc_relay_domain::{AdmissionSnapshot, RateBucket};
    let admission = AdmissionSnapshot::new(vec![
        (RateBucket::RegisteredCommand(identity.user_id), 100),
        (RateBucket::GuestMessage(identity.user_id), 100),
    ])?;
    let PlanDecision::NeedsExternal(requests) =
        agenc_relay_testkit::plan(context.domain(), identity, command()?, &admission, None)?
    else {
        return Err("the invite needed no external inputs".into());
    };
    let mut inputs = answer_external(&requests);
    inputs.invite_ids = vec![agenc_relay_types::InviteId::from_bytes([seed; 16])];
    let PlanDecision::Mutation(plan) = agenc_relay_testkit::plan(
        context.domain(),
        identity,
        command()?,
        &admission,
        Some(inputs),
    )?
    else {
        return Err("the invite was not a mutation".into());
    };
    Ok(plan)
}

/// Two invites into one channel, so a per-channel floor of one is below use.
fn two_invites(fixture: &mut StateCoreFixture) -> TestResult {
    let context = fixture.context_mut()?;
    let owner = seed_session(context, 1, "Owner", None)?;
    let _first = seed_session(context, 2, "GuestOne", None)?;
    let _second = seed_session(context, 3, "GuestTwo", None)?;
    let room = ChannelNameValue::parse("#floor")?;
    let join = || CanonicalCommand::join(vec![ChannelTarget::new(room.clone(), false)]);
    let PlanDecision::Mutation(plan) = plan_live(context, owner, &join)? else {
        return Err("the join was not a mutation".into());
    };
    apply_live_plan(context, plan)?;
    for (seed, guest) in [(21_u8, "GuestOne"), (22, "GuestTwo")] {
        let invite = || {
            Ok(CanonicalCommand::invite(
                NicknameValue::parse(guest)?,
                room.clone(),
            ))
        };
        let plan = plan_invite(context, owner, &invite, seed)?;
        apply_live_plan(context, plan)?;
    }
    let usage = context.domain().operational_usage()?;
    assert_eq!(usage.invites_per_channel, 2);
    Ok(())
}

fn tight_invite_parts(motd: &str) -> TestResult<crate::runtime_config::RuntimeConfigParts> {
    let mut parts = golden_parts("AgenC", Some(motd))?;
    let mut values = parts.operational_limits.values();
    values.invites_per_channel = 1;
    parts.operational_limits = OperationalLimits::new(values)?;
    Ok(parts)
}

#[test]
fn a_candidate_below_the_live_invite_count_is_rejected_for_current_use() -> TestResult {
    let (mut fixture, handle) = reloading()?;
    two_invites(&mut fixture)?;
    let state = fixture.state_mut()?;
    let prepared = PreparedReload::new(
        &handle.load(),
        golden_config()?,
        tight_invite_parts("Tight")?,
    )?;
    assert_eq!(
        signal(state, prepared)?,
        ReloadOutcome::Rejected(ReloadRejection::CurrentUse)
    );
    assert_eq!(handle.load().motd_arc(), None);
    Ok(())
}

#[tokio::test]
async fn an_audited_candidate_below_live_use_reserves_its_failure_and_finalizes_the_old_revision()
-> TestResult {
    let (mut fixture, handle) = reloading()?;
    two_invites(&mut fixture)?;
    let state = fixture.state_mut()?;
    let prepared = PreparedReload::new(
        &handle.load(),
        golden_config()?,
        tight_invite_parts("Tight")?,
    )?;
    let (reply, mut response) = oneshot::channel();
    let exit = state.step_reload_request(ReloadCoreRequest::ActivateAudited {
        prepared: Box::new(prepared),
        success_event: Box::new(audit_event(OutcomeSuccess, REHASH)?),
        failure_event: Box::new(audit_event(OutcomeFailure, REHASH)?),
        reply,
    });
    assert!(exit.is_none());
    assert!(state.activate_pending_reload().is_none());
    let AuditedReloadStart::Provisional(activation) = response.try_recv()? else {
        return Err("the audited reload was not provisional".into());
    };
    assert!(
        !activation.changes_live_state,
        "a failed reload never changes live state"
    );
    storage_owner_idle(&mut fixture).await?;
    let mut parts = fixture.take_run_parts()?;
    let state = &mut parts.state;
    let (reply, mut committed) = oneshot::channel();
    assert!(
        state
            .step_reload_request(ReloadCoreRequest::CommitOutcome { activation, reply })
            .is_none()
    );
    assert!(
        committed.try_recv().is_err(),
        "the failure outcome waits for storage"
    );
    let settled = parts.storage.recv().await.ok_or("storage closed")?;
    assert_eq!(settled.transaction_id, activation.transaction_id);
    let CompletionStep::Refresh(continuation) = state.step_completion(settled) else {
        return Err("the failure outcome did not settle".into());
    };
    state
        .complete_index_refresh(continuation)
        .map_err(|exit| format!("{exit:?}"))?;
    assert_eq!(
        committed.try_recv()?,
        Ok(AuditedReloadResult::Failure(ReloadRejection::CurrentUse))
    );
    let (reply, mut finalized) = oneshot::channel();
    assert!(
        state
            .step_reload_request(ReloadCoreRequest::Finalize { activation, reply })
            .is_none()
    );
    let previous = handle.load().revision();
    assert_eq!(finalized.try_recv()?, Ok(previous));
    assert_eq!(
        handle.load().motd_arc(),
        None,
        "the old snapshot stays live"
    );
    assert!(state.reload_provisional.is_none());
    Ok(())
}

#[test]
fn a_foreign_activation_never_matches_the_provisional_reload() -> TestResult {
    let (mut fixture, handle) = reloading()?;
    let state = fixture.state_mut()?;
    let prepared = PreparedReload::new(
        &handle.load(),
        golden_config()?,
        golden_parts("AgenC", Some("Audited"))?,
    )?;
    let (reply, mut response) = oneshot::channel();
    let _exit = state.step_reload_request(ReloadCoreRequest::ActivateAudited {
        prepared: Box::new(prepared),
        success_event: Box::new(audit_event(OutcomeSuccess, REHASH)?),
        failure_event: Box::new(audit_event(OutcomeFailure, REHASH)?),
        reply,
    });
    assert!(state.activate_pending_reload().is_none());
    let AuditedReloadStart::Provisional(activation) = response.try_recv()? else {
        return Err("the audited reload was not provisional".into());
    };
    let foreign = ReloadActivation {
        transaction_id: agenc_relay_types::TransactionId::from_bytes([0xEE; 16]),
        ..activation
    };
    let (reply, _response) = oneshot::channel();
    assert!(matches!(
        state.submit_reload_failure_after_rejection(foreign, ReloadRejection::Busy, reply),
        Some(StateCoreExit::Corrupt(_))
    ));
    assert!(
        state.reload_provisional.is_some(),
        "the provisional reload is kept"
    );
    Ok(())
}

fn audited_provisional(
    state: &mut StateCore,
    handle: &RuntimeConfigHandle,
) -> TestResult<ReloadActivation> {
    let prepared = PreparedReload::new(
        &handle.load(),
        golden_config()?,
        golden_parts("AgenC", Some("Provisional"))?,
    )?;
    let (reply, mut response) = oneshot::channel();
    let exit = state.step_reload_request(ReloadCoreRequest::ActivateAudited {
        prepared: Box::new(prepared),
        success_event: Box::new(audit_event(OutcomeSuccess, REHASH)?),
        failure_event: Box::new(audit_event(OutcomeFailure, REHASH)?),
        reply,
    });
    assert!(exit.is_none());
    assert!(state.activate_pending_reload().is_none());
    match response.try_recv()? {
        AuditedReloadStart::Provisional(activation) => Ok(activation),
        other => Err(format!("not provisional: {other:?}").into()),
    }
}

#[test]
fn a_provisional_reload_keeps_every_later_activation_busy() -> TestResult {
    let (mut fixture, handle) = reloading()?;
    let state = fixture.state_mut()?;
    let activation = audited_provisional(state, &handle)?;
    assert!(activation.changes_live_state);
    let prepared = PreparedReload::new(
        &handle.load(),
        golden_config()?,
        golden_parts("AgenC", Some("Second"))?,
    )?;
    let (reply, mut response) = oneshot::channel();
    assert!(
        state
            .step_reload_request(ReloadCoreRequest::ActivateSignal {
                prepared: Box::new(prepared),
                reply,
            })
            .is_none()
    );
    assert_eq!(
        response.try_recv()?,
        ReloadOutcome::Rejected(ReloadRejection::Busy)
    );
    let prepared = PreparedReload::new(
        &handle.load(),
        golden_config()?,
        golden_parts("AgenC", Some("Third"))?,
    )?;
    let (reply, mut response) = oneshot::channel();
    assert!(
        state
            .step_reload_request(ReloadCoreRequest::ActivateAudited {
                prepared: Box::new(prepared),
                success_event: Box::new(audit_event(OutcomeSuccess, REHASH)?),
                failure_event: Box::new(audit_event(OutcomeFailure, REHASH)?),
                reply,
            })
            .is_none()
    );
    assert_eq!(
        response.try_recv()?,
        AuditedReloadStart::Refused(ReloadRejection::Busy)
    );
    assert!(state.reload_pending.is_none());
    assert!(state.reload_provisional.is_some());
    Ok(())
}

#[test]
fn a_reload_inbox_cannot_be_installed_over_a_provisional_reload() -> TestResult {
    let (mut fixture, handle) = reloading()?;
    let state = fixture.state_mut()?;
    let _activation = audited_provisional(state, &handle)?;
    let admission = std::sync::Arc::new(crate::admission::TransportAdmission::new(
        handle.load().rates(),
        1,
        std::sync::Arc::new(crate::budget::MemoryBudget::new(64 * 1_024 * 1_024)),
        Box::new(crate::clock::SystemMonotonicClock::start()),
    )?);
    let (_port, inbox) = crate::runtime_config::reload_channel(handle, admission);
    assert_eq!(
        state.install_reload_inbox(inbox).err(),
        Some(crate::RuntimeError::InvalidValue)
    );
    Ok(())
}
