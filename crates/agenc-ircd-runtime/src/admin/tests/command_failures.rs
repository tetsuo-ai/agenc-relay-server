//! Reply and observation outcomes of read-only and immediate commands.
#![forbid(unsafe_code)]

use agenc_ircd_testkit::DeterministicWallClock;

use super::harness::{CoreReply, ENTITY, Session, handled};
use super::*;
use crate::test_support::TestResult;

#[tokio::test]
async fn a_refused_observed_audit_names_busy_or_invalid_target() -> TestResult {
    let mut session = Session::authenticated().await?;
    let cases = [
        (AdminCoreFailure::Busy, "BUSY :Administrative action busy"),
        (
            AdminCoreFailure::Quiescing,
            "BUSY :Administrative action busy",
        ),
        (
            AdminCoreFailure::InvalidTarget,
            "INVALID_TARGET :Administrative target unavailable",
        ),
        (
            AdminCoreFailure::StaleRevision,
            "INVALID_TARGET :Administrative target unavailable",
        ),
    ];
    for (counter, (failure, tail)) in (0_u64..).zip(cases) {
        let reply = session
            .command(counter, "MOTD", &[CoreReply::Next(Err(failure))])
            .await?;
        assert_eq!(reply, format!("FAIL MOTD {tail}"));
    }
    Ok(())
}

#[tokio::test]
async fn an_unavailable_audit_store_withholds_a_read_only_reply() -> TestResult {
    let mut session = Session::authenticated().await?;
    let reply = session
        .command(
            0,
            "VERSION",
            &[CoreReply::Next(Err(AdminCoreFailure::StorageUnavailable))],
        )
        .await?;
    assert_eq!(
        reply,
        "FAIL VERSION STORAGE_UNAVAILABLE :Administrative audit unavailable"
    );
    assert!(session.is_silent());
    Ok(())
}

#[tokio::test]
async fn an_unavailable_audit_store_answers_stats_with_its_selector() -> TestResult {
    let mut session = Session::authenticated().await?;
    let reply = session
        .command(
            0,
            "STATS QUEUES",
            &[
                CoreReply::Snapshot,
                CoreReply::Next(Err(AdminCoreFailure::StorageUnavailable)),
            ],
        )
        .await?;
    assert_eq!(
        reply,
        render_stats_storage_unavailable(StatsSelector::Queues)
    );
    Ok(())
}

#[tokio::test]
async fn a_full_state_core_queue_reports_stats_and_audits_busy() -> TestResult {
    let mut session = Session::authenticated().await?;
    session.saturate_core().await;
    let stats = session.command(0, "STATS RUNTIME", &[]).await?;
    assert_eq!(stats, "FAIL STATS BUSY RUNTIME :Administrative action busy");
    let links = session.command(1, "LINKS", &[]).await?;
    assert_eq!(links, "FAIL LINKS BUSY :Administrative action busy");
    Ok(())
}

#[tokio::test]
async fn a_failed_snapshot_reports_the_selector_unavailable() -> TestResult {
    let mut session = Session::authenticated().await?;
    let reply = session
        .command(0, "STATS FEDERATION", &[CoreReply::Next(Ok(()))])
        .await?;
    assert_eq!(reply, render_stats_unavailable(StatsSelector::Federation));
    Ok(())
}

#[tokio::test]
async fn a_stopped_state_core_reports_the_selector_unavailable() -> TestResult {
    let mut session = Session::authenticated().await?;
    let (core, inbox) = admin_core_channel();
    drop(inbox);
    session.owner.core = core;
    let reply = session.command(0, "STATS E2EE", &[]).await?;
    assert_eq!(reply, render_stats_unavailable(StatsSelector::E2ee));
    Ok(())
}

#[tokio::test]
async fn stats_without_entropy_for_a_batch_id_are_unavailable() -> TestResult {
    let mut session = Session::authenticated().await?;
    session.exhaust_entropy()?;
    let reply = session
        .command(0, "STATS RATES", &[CoreReply::Snapshot])
        .await?;
    assert_eq!(reply, render_stats_unavailable(StatsSelector::Rates));
    Ok(())
}

#[tokio::test]
async fn stats_without_a_sample_time_are_unavailable() -> TestResult {
    let mut session = Session::authenticated().await?;
    session.break_wall_clock();
    let reply = session
        .command(0, "STATS STORAGE", &[CoreReply::Snapshot])
        .await?;
    assert_eq!(reply, render_stats_unavailable(StatsSelector::Storage));
    Ok(())
}

#[tokio::test]
async fn every_stats_selector_renders_its_own_batch() -> TestResult {
    let mut session = Session::authenticated().await?;
    session.owner.entropy = Box::new(ScriptedEntropy::new(vec![0; 128])?);
    let selectors = [
        ("RUNTIME", 9_usize),
        ("STORAGE", 14),
        ("FEDERATION", 7),
        ("QUEUES", 10),
        ("RATES", 8),
        ("E2EE", 9),
    ];
    for (counter, (selector, fields)) in (0_u64..).zip(selectors) {
        let reply = session
            .command(
                counter,
                &format!("STATS {selector}"),
                &[CoreReply::Snapshot, CoreReply::Next(Ok(()))],
            )
            .await?;
        let opening = format!("agenc.ag/stats {selector} {fields} ");
        assert!(reply.lines().next().ok_or("opening")?.contains(&opening));
        assert_eq!(reply.lines().count(), fields + 2);
    }
    Ok(())
}

#[tokio::test]
async fn time_without_a_wall_clock_is_unavailable() -> TestResult {
    let mut session = Session::authenticated().await?;
    session.break_wall_clock();
    let reply = session.command(0, "TIME", &[]).await?;
    assert_eq!(reply, "FAIL TIME UNAVAILABLE :Command unavailable");
    Ok(())
}

#[tokio::test]
async fn a_read_only_command_without_an_audit_time_is_refused() -> TestResult {
    let mut session = Session::authenticated().await?;
    session.break_wall_clock();
    let reply = session.command(0, "VERSION", &[]).await?;
    assert_eq!(
        reply,
        "FAIL VERSION STORAGE_UNAVAILABLE :Administrative audit unavailable"
    );
    Ok(())
}

#[tokio::test]
async fn time_and_links_answer_after_their_audit_commits() -> TestResult {
    let mut session = Session::authenticated().await?;
    session.owner.wall = Box::new(DeterministicWallClock::at(1_700_000_000));
    let time = session
        .command(0, "TIME", &[CoreReply::Next(Ok(()))])
        .await?;
    assert_eq!(time, ":agenc-ircd 391 * agenc-ircd :1700000000");
    let links = session
        .command(1, "LINKS", &[CoreReply::Next(Ok(()))])
        .await?;
    assert!(links.starts_with(":agenc-ircd 371 * :Server topology is not exposed"));
    Ok(())
}

#[tokio::test]
async fn a_configured_motd_is_framed_by_its_numerics() -> TestResult {
    let mut session = Session::authenticated().await?;
    let snapshot = crate::test_support::golden_snapshot("AgenC", Some("maintenance at noon"))?;
    session.owner.config = Some(RuntimeConfigHandle::new(snapshot));
    let reply = session
        .command(0, "MOTD", &[CoreReply::Next(Ok(()))])
        .await?;
    let lines: Vec<&str> = reply.lines().collect();
    assert_eq!(
        lines.first().copied(),
        Some(":agenc-ircd 375 * :- agenc-ircd Message of the day -")
    );
    assert!(lines.contains(&":agenc-ircd 372 * :- maintenance at noon"));
    assert_eq!(
        lines.last().copied(),
        Some(":agenc-ircd 376 * :End of MOTD")
    );
    Ok(())
}

#[tokio::test]
async fn an_operator_without_the_permission_is_refused_in_place() -> TestResult {
    let mut session = Session::unauthenticated()?;
    session.owner.registry = registry()?;
    session.send(oper_line()?, &[]).await?;
    let reply = session
        .command(0, &format!("KILL {ENTITY} :abuse report"), &[])
        .await?;
    assert_eq!(reply, "FAIL KILL PRIVILEGES :Insufficient privileges");
    let next = session.command(1, "REHASH :reload now", &[]).await?;
    assert_eq!(next, "FAIL REHASH PRIVILEGES :Insufficient privileges");
    Ok(())
}

#[tokio::test]
async fn pre_auth_liveness_answers_ping_and_absorbs_pong() -> TestResult {
    let mut session = Session::unauthenticated()?;
    session.send(b"PING early\r\n".to_vec(), &[]).await?;
    assert_eq!(session.text()?, "PONG :early");
    session.send(b"PONG early\r\n".to_vec(), &[]).await?;
    assert!(session.is_silent());
    Ok(())
}

#[tokio::test]
async fn pre_auth_quit_closes_as_a_client_quit() -> TestResult {
    let mut session = Session::unauthenticated()?;
    session.send(b"QUIT\r\n".to_vec(), &[]).await?;
    let close = session.write()?;
    assert!(close.lines.is_empty());
    assert_eq!(close.close, Some(CloseReason::ClientQuit));
    Ok(())
}

#[tokio::test]
async fn signed_liveness_and_quit_need_no_audit_record() -> TestResult {
    let mut session = Session::authenticated().await?;
    assert_eq!(session.command(0, "PING alive", &[]).await?, "PONG :alive");
    session.send(signed_line(1, "PONG alive")?, &[]).await?;
    assert!(session.is_silent());
    session.send(signed_line(2, "QUIT")?, &[]).await?;
    assert_eq!(session.write()?.close, Some(CloseReason::ClientQuit));
    Ok(())
}

#[tokio::test]
async fn a_malformed_pre_auth_line_closes_as_a_protocol_error() -> TestResult {
    let mut session = Session::unauthenticated()?;
    session.send(b"HELLO there\r\n".to_vec(), &[]).await?;
    assert_eq!(session.write()?.close, Some(CloseReason::ProtocolError));
    Ok(())
}

#[tokio::test]
async fn a_line_for_an_unknown_generation_is_dropped() -> TestResult {
    let mut session = Session::unauthenticated()?;
    let stranger = ConnectionGeneration::new(4_000);
    session
        .owner
        .line(stranger, b"PING early\r\n", &session.root)
        .await;
    assert!(session.is_silent());
    assert_eq!(session.owner.sessions.len(), 1);
    Ok(())
}

#[tokio::test]
async fn link_commands_without_a_control_surface_are_unavailable() -> TestResult {
    let mut session = Session::authenticated().await?;
    let connect = session
        .command(0, &format!("CONNECT {ENTITY} :bring up"), &[])
        .await?;
    assert_eq!(connect, "FAIL CONNECT UNAVAILABLE :Command unavailable");
    let squit = session
        .command(1, &format!("SQUIT {ENTITY} :take down"), &[])
        .await?;
    assert_eq!(squit, "FAIL SQUIT UNAVAILABLE :Command unavailable");
    Ok(())
}

#[tokio::test]
async fn output_for_a_departed_session_is_observed_as_closed() -> TestResult {
    let session = Session::authenticated().await?;
    session
        .owner
        .command_observation
        .set(AdminCommandObservation::Pending);
    session.owner.output_line(
        ConnectionGeneration::new(4_001),
        "NOTE X OK :done".to_owned(),
    );
    assert!(matches!(
        session.owner.command_observation.get(),
        AdminCommandObservation::Complete(ResultClass::Closed)
    ));
    Ok(())
}

#[tokio::test]
async fn a_refusing_output_queue_is_observed_as_closed() -> TestResult {
    let mut session = Session::authenticated().await?;
    for _ in 0..ADMIN_OUTPUT_CAPACITY {
        session
            .owner
            .output_line(session.generation, "NOTE X OK :queued".to_owned());
    }
    session
        .owner
        .command_observation
        .set(AdminCommandObservation::Pending);
    session
        .owner
        .output_line(session.generation, "NOTE X OK :refused".to_owned());
    assert!(matches!(
        session.owner.command_observation.get(),
        AdminCommandObservation::Complete(ResultClass::Closed)
    ));
    let mut queued = 0_usize;
    while session.output.try_recv().is_ok() {
        queued += 1;
    }
    assert_eq!(queued, ADMIN_OUTPUT_CAPACITY);
    Ok(())
}

#[tokio::test]
async fn an_oversized_batch_is_refused_and_observed_as_closed() -> TestResult {
    let mut session = Session::authenticated().await?;
    session
        .owner
        .command_observation
        .set(AdminCommandObservation::Pending);
    let lines = vec!["NOTE X OK :line".to_owned(); MAX_ORDINARY_BATCH_LINES + 1];
    session.owner.output_batch(session.generation, lines);
    assert!(matches!(
        session.owner.command_observation.get(),
        AdminCommandObservation::Complete(ResultClass::Closed)
    ));
    assert_eq!(session.write()?.close, Some(CloseReason::SlowConsumer));
    Ok(())
}

#[test]
fn a_command_observation_keeps_its_most_severe_result() -> TestResult {
    let owner = lifecycle_owner()?;
    owner.record_command_result(ResultClass::Error);
    assert!(matches!(
        owner.command_observation.get(),
        AdminCommandObservation::Inactive
    ));
    owner
        .command_observation
        .set(AdminCommandObservation::Pending);
    owner.record_command_result(ResultClass::Rejected);
    owner.record_command_result(ResultClass::Ok);
    assert!(matches!(
        owner.command_observation.get(),
        AdminCommandObservation::Complete(ResultClass::Rejected)
    ));
    owner.record_command_result(ResultClass::Error);
    owner.record_command_result(ResultClass::Closed);
    assert!(matches!(
        owner.command_observation.get(),
        AdminCommandObservation::Complete(ResultClass::Error)
    ));
    Ok(())
}

#[test]
fn closing_a_departed_session_queues_nothing() -> TestResult {
    let owner = lifecycle_owner()?;
    owner.close(ConnectionGeneration::new(4_002), CloseReason::ProtocolError);
    assert!(owner.sessions.is_empty());
    Ok(())
}

#[tokio::test]
async fn refusals_and_failures_are_observed_under_their_result_class() -> TestResult {
    let mut session = Session::unauthenticated()?;
    let (metrics, _log) = session.observe();
    session.owner.registry = registry()?;
    session.send(oper_line()?, &[]).await?;
    session
        .command(0, &format!("KILL {ENTITY} :abuse report"), &[])
        .await?;
    session
        .command(1, "MOTD", &[CoreReply::Next(Err(AdminCoreFailure::Busy))])
        .await?;
    session
        .command(
            2,
            "MOTD",
            &[CoreReply::Next(Err(AdminCoreFailure::StorageUnavailable))],
        )
        .await?;
    session.command(3, "PING alive", &[]).await?;
    session.send(signed_line(4, "QUIT")?, &[]).await?;
    assert_eq!(handled(&metrics, ResultClass::Rejected)?, 1);
    assert_eq!(handled(&metrics, ResultClass::Busy)?, 1);
    assert_eq!(handled(&metrics, ResultClass::Error)?, 1);
    assert_eq!(handled(&metrics, ResultClass::Ok)?, 1);
    assert_eq!(handled(&metrics, ResultClass::Closed)?, 0);
    Ok(())
}
