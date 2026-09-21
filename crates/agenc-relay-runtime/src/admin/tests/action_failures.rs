//! Intent, action, and outcome failures of audited administrative actions.
#![forbid(unsafe_code)]

use agenc_relay_testkit::DeterministicWallClock;

use super::harness::{ACCOUNT, CoreReply, ENTITY, Session};
use super::*;
use crate::test_support::TestResult;

const STORAGE_UNAVAILABLE: &str = "STORAGE_UNAVAILABLE :Administrative audit unavailable";

fn kill() -> String {
    format!("KILL {ENTITY} :abuse report")
}

fn restore() -> String {
    format!("ACCOUNT RESTORE {ACCOUNT} :ok now")
}

fn quarantine() -> String {
    format!("CHANNEL QUARANTINE {ENTITY} :x y")
}

fn purge() -> String {
    format!("CHANNEL HISTORY PURGE {ENTITY} :retention request")
}

fn assert_failed_closed(session: &mut Session, fatal: &mut mpsc::Receiver<()>) -> TestResult {
    let mut closed = false;
    while let Ok(write) = session.output.try_recv() {
        closed |= write.close == Some(CloseReason::ProtocolError);
    }
    assert!(closed, "the session was not closed");
    fatal.try_recv()?;
    Ok(())
}

async fn federated_session() -> TestResult<Session> {
    let mut session = Session::authenticated().await?;
    let peer = ServerId::parse(ENTITY).map_err(|_| "peer")?;
    let control = FederationControl::new(agenc_relay_types::FederationRole::Edge, [peer]);
    session.owner.install_federation_control(control)?;
    Ok(session)
}

#[tokio::test]
async fn a_refused_kill_intent_stops_before_the_kill() -> TestResult {
    let mut session = Session::authenticated().await?;
    let reply = session
        .command(0, &kill(), &[CoreReply::Next(Err(AdminCoreFailure::Busy))])
        .await?;
    assert_eq!(reply, "FAIL KILL BUSY :Administrative action busy");
    assert!(session.is_silent());
    Ok(())
}

#[tokio::test]
async fn a_kill_answers_after_intent_action_and_outcome() -> TestResult {
    let mut session = Session::authenticated().await?;
    let committed = [CoreReply::Next(Ok(())); 3];
    let reply = session.command(0, &kill(), &committed).await?;
    assert_eq!(reply, "NOTE KILL OK :Session terminated");
    Ok(())
}

#[tokio::test]
async fn a_failed_kill_is_reported_after_its_failure_outcome() -> TestResult {
    let mut session = Session::authenticated().await?;
    let replies = [
        CoreReply::Next(Ok(())),
        CoreReply::Next(Err(AdminCoreFailure::InvalidTarget)),
        CoreReply::Next(Ok(())),
    ];
    let reply = session.command(0, &kill(), &replies).await?;
    assert_eq!(
        reply,
        "FAIL KILL INVALID_TARGET :Administrative target unavailable"
    );
    Ok(())
}

#[tokio::test]
async fn an_uncommitted_kill_outcome_fails_closed() -> TestResult {
    let mut session = Session::authenticated().await?;
    let mut fatal = session.watch_fatal();
    let replies = [
        CoreReply::Next(Ok(())),
        CoreReply::Next(Ok(())),
        CoreReply::Next(Err(AdminCoreFailure::StorageUnavailable)),
    ];
    session.send(signed_line(0, &kill())?, &replies).await?;
    assert_failed_closed(&mut session, &mut fatal)
}

#[tokio::test]
async fn a_kill_without_an_audit_time_never_reaches_the_core() -> TestResult {
    let mut session = Session::authenticated().await?;
    session.break_wall_clock();
    let reply = session.command(0, &kill(), &[]).await?;
    assert_eq!(reply, format!("FAIL KILL {STORAGE_UNAVAILABLE}"));
    Ok(())
}

#[tokio::test]
async fn a_kill_outcome_without_an_audit_time_fails_closed() -> TestResult {
    let mut session = Session::authenticated().await?;
    let mut fatal = session.watch_fatal();
    session.expire_wall_clock_after(1);
    let replies = [CoreReply::Next(Ok(())); 2];
    let reply = session.command(0, &kill(), &replies).await?;
    assert_eq!(reply, format!("FAIL KILL {STORAGE_UNAVAILABLE}"));
    assert_failed_closed(&mut session, &mut fatal)
}

#[tokio::test]
async fn a_second_federation_control_is_refused() -> TestResult {
    let mut session = federated_session().await?;
    let control = FederationControl::new(agenc_relay_types::FederationRole::Edge, []);
    assert!(matches!(
        session.owner.install_federation_control(control),
        Err(RuntimeError::InvalidValue)
    ));
    Ok(())
}

#[tokio::test]
async fn a_refused_link_intent_stops_before_the_link_action() -> TestResult {
    let mut session = federated_session().await?;
    let reply = session
        .command(
            0,
            &format!("CONNECT {ENTITY} :bring up"),
            &[CoreReply::Next(Err(AdminCoreFailure::Quiescing))],
        )
        .await?;
    assert_eq!(reply, "FAIL CONNECT BUSY :Administrative action busy");
    Ok(())
}

#[tokio::test]
async fn an_uncommitted_link_outcome_fails_closed() -> TestResult {
    let mut session = federated_session().await?;
    let mut fatal = session.watch_fatal();
    let replies = [
        CoreReply::Next(Ok(())),
        CoreReply::Next(Err(AdminCoreFailure::Busy)),
    ];
    let line = signed_line(0, &format!("CONNECT {ENTITY} :bring up"))?;
    session.send(line, &replies).await?;
    assert_failed_closed(&mut session, &mut fatal)
}

#[tokio::test]
async fn a_link_command_without_an_audit_time_is_refused() -> TestResult {
    let mut session = federated_session().await?;
    session.break_wall_clock();
    let reply = session
        .command(0, &format!("SQUIT {ENTITY} :take down"), &[])
        .await?;
    assert_eq!(reply, format!("FAIL SQUIT {STORAGE_UNAVAILABLE}"));
    Ok(())
}

#[tokio::test]
async fn an_account_restore_commits_at_the_current_revision() -> TestResult {
    let mut session = Session::authenticated().await?;
    let replies = [CoreReply::Revision(3), CoreReply::Mutation(Ok(()))];
    let reply = session.command(0, &restore(), &replies).await?;
    assert_eq!(reply, "NOTE ACCOUNT OK :Account restored");
    Ok(())
}

#[tokio::test]
async fn an_unconfirmed_mutation_retries_once_at_a_fresh_revision() -> TestResult {
    let mut session = Session::authenticated().await?;
    let stale = CoreReply::Mutation(Err(AdminCoreFailure::StaleRevision));
    let replies = [
        CoreReply::Revision(3),
        stale,
        CoreReply::Revision(4),
        CoreReply::Mutation(Ok(())),
    ];
    let reply = session.command(0, &restore(), &replies).await?;
    assert_eq!(reply, "NOTE ACCOUNT OK :Account restored");

    let replies = [CoreReply::Revision(5), stale, CoreReply::Revision(6), stale];
    let reply = session.command(1, &restore(), &replies).await?;
    assert_eq!(
        reply,
        "FAIL ACCOUNT INVALID_TARGET :Administrative target unavailable"
    );
    Ok(())
}

#[tokio::test]
async fn a_stale_retry_without_a_fresh_revision_is_refused() -> TestResult {
    let mut session = Session::authenticated().await?;
    let replies = [
        CoreReply::Revision(3),
        CoreReply::Mutation(Err(AdminCoreFailure::StaleRevision)),
        CoreReply::Next(Ok(())),
    ];
    let reply = session.command(0, &restore(), &replies).await?;
    assert_eq!(reply, format!("FAIL ACCOUNT {STORAGE_UNAVAILABLE}"));
    Ok(())
}

#[tokio::test]
async fn an_account_mutation_without_a_target_revision_is_refused() -> TestResult {
    let mut session = Session::authenticated().await?;
    let reply = session
        .command(0, &restore(), &[CoreReply::Next(Ok(()))])
        .await?;
    assert_eq!(reply, format!("FAIL ACCOUNT {STORAGE_UNAVAILABLE}"));
    Ok(())
}

#[tokio::test]
async fn an_account_mutation_without_an_audit_time_is_refused() -> TestResult {
    let mut session = Session::authenticated().await?;
    session.break_wall_clock();
    let reply = session
        .command(0, &restore(), &[CoreReply::Revision(3)])
        .await?;
    assert_eq!(reply, format!("FAIL ACCOUNT {STORAGE_UNAVAILABLE}"));
    Ok(())
}

#[tokio::test]
async fn a_suspension_expiry_beyond_the_time_domain_is_refused() -> TestResult {
    let mut session = Session::authenticated().await?;
    session.owner.wall = Box::new(DeterministicWallClock::at(u64::MAX - 5));
    let suspend = format!("ACCOUNT SUSPEND {ACCOUNT} 2592000 :spam wave");
    let reply = session
        .command(0, &suspend, &[CoreReply::Revision(3)])
        .await?;
    assert_eq!(reply, format!("FAIL ACCOUNT {STORAGE_UNAVAILABLE}"));
    Ok(())
}

#[tokio::test]
async fn a_short_suspension_commits_without_confirmation() -> TestResult {
    let mut session = Session::authenticated().await?;
    let suspend = format!("ACCOUNT SUSPEND {ACCOUNT} 2592000 :spam wave");
    let replies = [CoreReply::Revision(3), CoreReply::Mutation(Ok(()))];
    let reply = session.command(0, &suspend, &replies).await?;
    assert_eq!(reply, "NOTE ACCOUNT OK :Account suspended");
    let busy = [
        CoreReply::Revision(4),
        CoreReply::Mutation(Err(AdminCoreFailure::Busy)),
    ];
    let reply = session.command(1, &suspend, &busy).await?;
    assert_eq!(reply, "FAIL ACCOUNT BUSY :Administrative action busy");
    Ok(())
}

#[tokio::test]
async fn a_channel_quarantine_reports_its_commit_outcome() -> TestResult {
    let mut session = Session::authenticated().await?;
    let replies = [CoreReply::Revision(3), CoreReply::Mutation(Ok(()))];
    let reply = session.command(0, &quarantine(), &replies).await?;
    assert_eq!(reply, "NOTE CHANNEL OK :Channel quarantined");
    let refused = [
        CoreReply::Revision(4),
        CoreReply::Mutation(Err(AdminCoreFailure::InvalidTarget)),
    ];
    let reply = session.command(1, &quarantine(), &refused).await?;
    assert_eq!(
        reply,
        "FAIL CHANNEL INVALID_TARGET :Administrative target unavailable"
    );
    Ok(())
}

#[tokio::test]
async fn a_channel_mutation_without_an_audit_time_is_refused() -> TestResult {
    let mut session = Session::authenticated().await?;
    session.break_wall_clock();
    let reply = session
        .command(0, &quarantine(), &[CoreReply::Revision(3)])
        .await?;
    assert_eq!(reply, format!("FAIL CHANNEL {STORAGE_UNAVAILABLE}"));
    Ok(())
}

#[tokio::test]
async fn a_channel_mutation_without_a_target_revision_is_refused() -> TestResult {
    let mut session = Session::authenticated().await?;
    let reply = session
        .command(0, &quarantine(), &[CoreReply::Next(Ok(()))])
        .await?;
    assert_eq!(reply, format!("FAIL CHANNEL {STORAGE_UNAVAILABLE}"));
    Ok(())
}

#[tokio::test]
async fn a_confirmed_purge_is_never_retried_at_a_newer_revision() -> TestResult {
    let mut session = Session::authenticated().await?;
    session.request_confirmation(&purge()).await?;
    let stale = [CoreReply::Mutation(Err(AdminCoreFailure::StaleRevision))];
    session.confirm(&purge(), &stale).await?;
    assert_eq!(
        session.text()?,
        "FAIL CHANNEL INVALID_TARGET :Administrative target unavailable"
    );
    Ok(())
}

#[tokio::test]
async fn a_confirmed_purge_commits_at_the_confirmed_revision() -> TestResult {
    let mut session = Session::authenticated().await?;
    session.request_confirmation(&purge()).await?;
    session
        .confirm(&purge(), &[CoreReply::Mutation(Ok(()))])
        .await?;
    assert_eq!(session.text()?, "NOTE CHANNEL OK :Channel history purged");
    Ok(())
}
