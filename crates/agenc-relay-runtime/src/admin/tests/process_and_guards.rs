//! Process actions, confirmation issue, unavailable capabilities, and the
//! owner's defensive audit-phase guards.
#![forbid(unsafe_code)]

use super::harness::{CoreReply, ENTITY, Session, command_event, drive};
use super::*;
use crate::test_support::TestResult;

const DIE: &str = "DIE :planned maintenance";
const RESTART: &str = "RESTART :planned maintenance";
const STORAGE_UNAVAILABLE: &str = "STORAGE_UNAVAILABLE :Administrative audit unavailable";

fn closes_with(session: &mut Session, reason: CloseReason) -> bool {
    let mut closed = false;
    while let Ok(write) = session.output.try_recv() {
        closed |= write.close == Some(reason);
    }
    closed
}

fn export(text: &str) -> TestResult<AdminWrite> {
    AdminWrite::export(vec![text.to_owned()], export_memory()?).map_err(|_| "export".into())
}

async fn confirmable_process_session() -> TestResult<(Session, AdminProcessInbox)> {
    let mut session = Session::authenticated().await?;
    let (process, inbox) = admin_process_channel();
    session.owner.process = Some(process);
    Ok((session, inbox))
}

#[tokio::test]
async fn a_confirmed_die_without_a_process_port_is_unavailable() -> TestResult {
    let mut session = Session::authenticated().await?;
    session.request_confirmation(DIE).await?;
    session.confirm(DIE, &[]).await?;
    assert_eq!(session.text()?, "FAIL DIE UNAVAILABLE :Command unavailable");
    Ok(())
}

#[tokio::test]
async fn a_process_revision_that_moved_voids_the_confirmation() -> TestResult {
    let (mut session, mut process) = confirmable_process_session().await?;
    session.request_confirmation(DIE).await?;
    session.confirm(DIE, &[CoreReply::Revision(10)]).await?;
    assert_eq!(
        session.text()?,
        "FAIL DIE INVALID_TARGET :Administrative target unavailable"
    );
    assert!(process.receiver.try_recv().is_err());
    Ok(())
}

#[tokio::test]
async fn a_process_action_without_a_current_revision_is_refused() -> TestResult {
    let (mut session, _process) = confirmable_process_session().await?;
    session.request_confirmation(RESTART).await?;
    session.confirm(RESTART, &[CoreReply::Next(Ok(()))]).await?;
    assert_eq!(
        session.text()?,
        format!("FAIL RESTART {STORAGE_UNAVAILABLE}")
    );
    Ok(())
}

#[tokio::test]
async fn a_refused_process_intent_leaves_the_daemon_running() -> TestResult {
    let (mut session, mut process) = confirmable_process_session().await?;
    session.request_confirmation(DIE).await?;
    let replies = [
        CoreReply::Revision(9),
        CoreReply::Next(Err(AdminCoreFailure::Busy)),
    ];
    session.confirm(DIE, &replies).await?;
    assert_eq!(session.text()?, "FAIL DIE BUSY :Administrative action busy");
    assert!(process.receiver.try_recv().is_err());
    assert!(!session.owner.quiescing);
    Ok(())
}

#[tokio::test]
async fn a_process_intent_without_an_audit_time_is_refused() -> TestResult {
    let (mut session, mut process) = confirmable_process_session().await?;
    session.request_confirmation(DIE).await?;
    session.break_wall_clock();
    session.confirm(DIE, &[CoreReply::Revision(9)]).await?;
    assert_eq!(session.text()?, format!("FAIL DIE {STORAGE_UNAVAILABLE}"));
    assert!(process.receiver.try_recv().is_err());
    Ok(())
}

#[tokio::test]
async fn a_confirmed_restart_quiesces_and_requests_the_restart() -> TestResult {
    let (mut session, mut process) = confirmable_process_session().await?;
    session.request_confirmation(RESTART).await?;
    let replies = [CoreReply::Revision(9), CoreReply::Next(Ok(()))];
    session.confirm(RESTART, &replies).await?;
    assert_eq!(
        process.receiver.try_recv().ok(),
        Some(AdminProcessAction::Restart)
    );
    assert!(session.owner.quiescing);
    assert!(session.is_silent());
    Ok(())
}

#[tokio::test]
async fn an_unconfirmed_process_action_is_a_protocol_error() -> TestResult {
    let (mut session, mut process) = confirmable_process_session().await?;
    let event = command_event(&signed_line(0, DIE)?)?;
    assert_eq!(event.confirmation, ConfirmationState::Required);
    let Session {
        owner,
        core,
        root,
        generation,
        ..
    } = &mut session;
    let work = owner.process_action(*generation, &event, AdminProcessAction::Die, root);
    drive(work, core, &[]).await?;
    assert!(closes_with(&mut session, CloseReason::ProtocolError));
    assert!(process.receiver.try_recv().is_err());
    Ok(())
}

#[tokio::test]
async fn a_confirmation_without_entropy_issues_no_token() -> TestResult {
    let mut session = Session::authenticated().await?;
    session.exhaust_entropy()?;
    let reply = session.command(0, DIE, &[CoreReply::Revision(9)]).await?;
    assert_eq!(reply, format!("FAIL DIE {STORAGE_UNAVAILABLE}"));
    Ok(())
}

#[tokio::test]
async fn a_confirmation_without_a_target_revision_issues_no_token() -> TestResult {
    let mut session = Session::authenticated().await?;
    let reply = session
        .command(0, RESTART, &[CoreReply::Next(Ok(()))])
        .await?;
    assert_eq!(reply, format!("FAIL RESTART {STORAGE_UNAVAILABLE}"));
    Ok(())
}

#[tokio::test]
async fn a_confirmation_for_an_unconfirmable_command_is_a_protocol_error() -> TestResult {
    let mut session = Session::authenticated().await?;
    let event = command_event(&signed_line(0, "MOTD")?)?;
    let Session {
        owner,
        core,
        root,
        generation,
        ..
    } = &mut session;
    drive(
        owner.issue_confirmation(*generation, &event, root),
        core,
        &[],
    )
    .await?;
    assert!(closes_with(&mut session, CloseReason::ProtocolError));
    Ok(())
}

#[tokio::test]
async fn a_confirmation_for_a_departed_session_is_dropped() -> TestResult {
    let mut session = Session::authenticated().await?;
    let event = command_event(&signed_line(0, DIE)?)?;
    let departed = ConnectionGeneration::new(4_003);
    let Session {
        owner, core, root, ..
    } = &mut session;
    let work = owner.issue_confirmation(departed, &event, root);
    drive(work, core, &[CoreReply::Revision(9)]).await?;
    assert!(session.is_silent());
    Ok(())
}

#[tokio::test]
async fn backup_and_rehash_without_their_runtime_are_unavailable() -> TestResult {
    let mut session = Session::authenticated().await?;
    let backup = session
        .command(0, "BACKUP CREATE :nightly run", &[])
        .await?;
    assert_eq!(backup, "FAIL BACKUP UNAVAILABLE :Command unavailable");
    let rehash = session.command(1, "REHASH :reload now", &[]).await?;
    assert_eq!(rehash, format!("FAIL REHASH {STORAGE_UNAVAILABLE}"));
    Ok(())
}

#[tokio::test]
async fn an_export_beyond_the_memory_budget_is_busy() -> TestResult {
    let mut session = Session::authenticated().await?;
    session.owner.budget = Arc::new(MemoryBudget::new(1));
    let reply = session.command(0, "AUDIT EXPORT 0 10", &[]).await?;
    assert_eq!(reply, "FAIL AUDIT BUSY :Administrative action busy");
    Ok(())
}

#[tokio::test]
async fn an_export_without_entropy_for_a_batch_id_is_refused() -> TestResult {
    let mut session = Session::authenticated().await?;
    session.owner.budget = Arc::new(MemoryBudget::new(MAX_AUDIT_EXPORT_BYTES * 4));
    session.exhaust_entropy()?;
    let reply = session.command(0, "AUDIT EXPORT 0 10", &[]).await?;
    assert_eq!(reply, format!("FAIL AUDIT {STORAGE_UNAVAILABLE}"));
    Ok(())
}

#[tokio::test]
async fn an_export_without_a_verified_source_fails_closed() -> TestResult {
    let mut session = Session::authenticated().await?;
    session.owner.budget = Arc::new(MemoryBudget::new(MAX_AUDIT_EXPORT_BYTES * 4));
    let mut fatal = session.watch_fatal();
    session
        .send(signed_line(0, "AUDIT EXPORT 0 10")?, &[])
        .await?;
    assert!(closes_with(&mut session, CloseReason::ProtocolError));
    fatal.try_recv()?;
    Ok(())
}

#[tokio::test]
async fn export_failures_map_to_closed_reply_codes() -> TestResult {
    let mut session = Session::authenticated().await?;
    let generation = session.generation;
    let storage = RuntimeError::Storage(StorageError::Unavailable);
    session.owner.output_export_failure(generation, storage);
    assert_eq!(session.text()?, format!("FAIL AUDIT {STORAGE_UNAVAILABLE}"));
    for error in [RuntimeError::LimitExceeded, RuntimeError::MemoryExhausted] {
        session.owner.output_export_failure(generation, error);
        assert_eq!(
            session.text()?,
            "FAIL AUDIT UNAVAILABLE :Audit export unavailable"
        );
    }
    session
        .owner
        .output_export_failure(generation, RuntimeError::Cancelled);
    assert!(closes_with(&mut session, CloseReason::ProtocolError));
    Ok(())
}

#[tokio::test]
async fn a_prepared_export_is_delivered_whole_or_observed_as_closed() -> TestResult {
    let mut session = Session::authenticated().await?;
    let generation = session.generation;
    session
        .owner
        .command_observation
        .set(AdminCommandObservation::Pending);
    session
        .owner
        .output_export(ConnectionGeneration::new(4_004), export("BATCH +x")?);
    assert!(matches!(
        session.owner.command_observation.get(),
        AdminCommandObservation::Complete(ResultClass::Closed)
    ));
    for _ in 0..ADMIN_OUTPUT_CAPACITY {
        session.owner.output_export(generation, export("BATCH +x")?);
    }
    session.owner.output_export(generation, export("BATCH +y")?);
    let mut delivered = 0_usize;
    while let Ok(write) = session.output.try_recv() {
        assert_eq!(write.lines, vec![b"BATCH +x".to_vec()]);
        delivered += 1;
    }
    assert_eq!(delivered, ADMIN_OUTPUT_CAPACITY);
    Ok(())
}

#[tokio::test]
async fn an_audit_phase_a_command_never_records_fails_closed() -> TestResult {
    let mut session = Session::authenticated().await?;
    let mut fatal = session.watch_fatal();
    let generation = session.generation;
    let motd = command_event(&signed_line(0, "MOTD")?)?;
    let kill = command_event(&signed_line(0, &format!("KILL {ENTITY} :abuse report"))?)?;
    let owner = &mut session.owner;
    assert!(
        owner
            .prepare_action_event(generation, &motd, AdminAuditPhase::Intent)
            .is_none()
    );
    fatal.try_recv()?;
    assert!(owner.prepare_observed_event(generation, &kill).is_none());
    fatal.try_recv()?;
    assert!(owner.prepare_rehash_outcomes(generation, &motd).is_none());
    fatal.try_recv()?;
    assert!(closes_with(&mut session, CloseReason::ProtocolError));
    Ok(())
}

#[tokio::test]
async fn an_audit_record_for_an_unauthenticated_session_is_a_protocol_error() -> TestResult {
    let mut session = Session::unauthenticated()?;
    let generation = session.generation;
    let motd = command_event(&signed_line(0, "MOTD")?)?;
    let kill = command_event(&signed_line(0, &format!("KILL {ENTITY} :abuse report"))?)?;
    let owner = &mut session.owner;
    assert!(owner.prepare_observed_event(generation, &motd).is_none());
    assert!(
        owner
            .prepare_action_event(generation, &kill, AdminAuditPhase::Intent)
            .is_none()
    );
    assert!(owner.prepare_rehash_outcomes(generation, &kill).is_none());
    let mut closes = 0_usize;
    while let Ok(write) = session.output.try_recv() {
        assert_eq!(write.close, Some(CloseReason::ProtocolError));
        closes += 1;
    }
    assert_eq!(closes, 3);
    Ok(())
}

#[tokio::test]
async fn rehash_outcomes_without_an_audit_time_are_refused() -> TestResult {
    let mut session = Session::authenticated().await?;
    session.break_wall_clock();
    let rehash = command_event(&signed_line(0, "REHASH :reload now")?)?;
    let generation = session.generation;
    assert!(
        session
            .owner
            .prepare_rehash_outcomes(generation, &rehash)
            .is_none()
    );
    assert_eq!(
        session.text()?,
        format!("FAIL REHASH {STORAGE_UNAVAILABLE}")
    );
    Ok(())
}

#[tokio::test]
async fn a_channel_mutation_for_another_command_fails_closed() -> TestResult {
    let mut session = Session::authenticated().await?;
    let mut fatal = session.watch_fatal();
    let motd = command_event(&signed_line(0, "MOTD")?)?;
    let channel = agenc_relay_types::ChannelInstanceId::parse(ENTITY).map_err(|_| "channel")?;
    let Session {
        owner,
        core,
        root,
        generation,
        ..
    } = &mut session;
    let work = owner.mutate_channel(*generation, &motd, channel, root);
    drive(work, core, &[]).await?;
    assert!(closes_with(&mut session, CloseReason::ProtocolError));
    fatal.try_recv()?;
    Ok(())
}

#[tokio::test]
async fn reload_refusals_render_closed_reply_codes() -> TestResult {
    let mut session = Session::authenticated().await?;
    let generation = session.generation;
    let busy = "FAIL REHASH BUSY :Administrative action busy";
    let invalid = "FAIL REHASH INVALID_CONFIG :Configuration rejected";
    let unavailable = "FAIL REHASH STORAGE_UNAVAILABLE :Administrative reload unavailable";
    let prepare = [
        (ReloadPrepareFailure::Busy, busy),
        (ReloadPrepareFailure::Unavailable, unavailable),
        (ReloadPrepareFailure::InvalidConfig, invalid),
        (ReloadPrepareFailure::StorageFloor, invalid),
        (
            ReloadPrepareFailure::RestartMaterialChanged,
            "FAIL REHASH RESTART_REQUIRED :Configuration requires restart",
        ),
    ];
    for (failure, line) in prepare {
        session
            .owner
            .output_reload_prepare_failure(generation, failure);
        assert_eq!(session.text()?, line);
    }
    let rejections = [
        (ReloadRejection::Busy, busy),
        (ReloadRejection::Quiescing, busy),
        (ReloadRejection::StaleRevision, busy),
        (ReloadRejection::CurrentUse, invalid),
        (ReloadRejection::StorageUnavailable, unavailable),
    ];
    for (rejection, line) in rejections {
        session.owner.output_reload_rejection(generation, rejection);
        assert_eq!(session.text()?, line);
    }
    Ok(())
}
