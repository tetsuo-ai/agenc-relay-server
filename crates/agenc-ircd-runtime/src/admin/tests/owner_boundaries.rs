//! Admission, lifecycle, authority reconciliation, and transport boundaries
//! of the administrative owner.
#![forbid(unsafe_code)]

use std::io::Write as _;

use agenc_ircd_testkit::DeterministicWallClock;

use super::harness::{Session, local_peer};
use super::*;
use crate::runtime_config::ConfigRevision;
use crate::test_support::{TestResult, golden_snapshot};

fn output() -> (AdminOutput, mpsc::Receiver<AdminWrite>) {
    let (sender, receiver) = mpsc::channel(ADMIN_OUTPUT_CAPACITY);
    (AdminOutput::new(sender), receiver)
}

fn lifecycle_request(phase: AdminLifecyclePhase) -> AdminLifecycleRequest {
    let (reply, _response) = oneshot::channel();
    AdminLifecycleRequest { phase, reply }
}

fn touch(directory: &BackupTestDirectory, name: &str) -> TestResult {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.0.join(name))?;
    file.write_all(b"not a signed backup")?;
    Ok(())
}

#[test]
fn a_lifecycle_batch_stops_collecting_at_its_capacity() -> TestResult {
    let (control, mut inbox) = admin_lifecycle_channel();
    for _ in 0..ADMIN_LIFECYCLE_CAPACITY {
        control
            .sender
            .try_send(lifecycle_request(AdminLifecyclePhase::Quiesce))
            .map_err(|_| "queue")?;
    }
    let mut batch = AdminLifecycleBatch::new(lifecycle_request(AdminLifecyclePhase::Drain));
    batch.collect_queued(&mut inbox.receiver);
    assert_eq!(batch.len, ADMIN_LIFECYCLE_BATCH_CAPACITY);
    assert!(!batch.contains_stop());
    assert_eq!(
        batch.into_requests().count(),
        ADMIN_LIFECYCLE_BATCH_CAPACITY
    );
    Ok(())
}

#[tokio::test]
async fn a_direct_stop_completes_and_quiesces() -> TestResult {
    let mut owner = lifecycle_owner()?;
    let root = CancellationToken::root();
    assert!(matches!(
        owner
            .lifecycle_outcome(AdminLifecyclePhase::Stop, &root)
            .await,
        Ok(AdminLifecycleOutcome::Complete)
    ));
    assert!(owner.quiescing);
    assert_eq!(owner.lifecycle_completed, Some(AdminLifecyclePhase::Stop));
    let request = lifecycle_request(AdminLifecyclePhase::Stop);
    assert!(owner.handle_lifecycle(request, &root).await);
    Ok(())
}

#[tokio::test]
async fn a_flush_before_any_drain_first_queues_the_shutdown_frame() -> TestResult {
    let mut session = Session::unauthenticated()?;
    let outcome = session
        .owner
        .lifecycle_outcome(AdminLifecyclePhase::Flush, &session.root)
        .await;
    assert!(matches!(outcome, Ok(AdminLifecycleOutcome::Complete)));
    assert_eq!(
        session.owner.lifecycle_completed,
        Some(AdminLifecyclePhase::Flush)
    );
    let shutdown = session.write()?;
    assert_eq!(shutdown.close, Some(CloseReason::Shutdown));
    assert_eq!(
        shutdown.lines,
        vec![ADMIN_SHUTDOWN_LINE.as_bytes().to_vec()]
    );
    Ok(())
}

#[tokio::test]
async fn a_drain_with_a_lost_writer_reports_a_writer_failure() -> TestResult {
    let mut session = Session::unauthenticated()?;
    session.output.close();
    let outcome = session
        .owner
        .lifecycle_outcome(AdminLifecyclePhase::Drain, &session.root)
        .await;
    assert!(matches!(outcome, Err(AdminLifecycleFailure::Writer)));
    assert_eq!(
        session.owner.lifecycle_completed,
        Some(AdminLifecyclePhase::Quiesce)
    );
    Ok(())
}

#[tokio::test]
async fn a_quiescing_owner_refuses_new_sessions_and_lines() -> TestResult {
    let mut session = Session::unauthenticated()?;
    session.owner.quiescing = true;
    let (newcomer, mut refused) = output();
    let opened = AdminOwnerMessage::Opened {
        generation: ConnectionGeneration::new(41),
        challenge: challenge(),
        peer: local_peer(),
        output: newcomer,
    };
    session.owner.handle(opened, &session.root).await;
    assert_eq!(refused.try_recv()?.close, Some(CloseReason::Shutdown));
    assert_eq!(session.owner.sessions.len(), 1);

    let line = AdminOwnerMessage::Line {
        generation: session.generation,
        line: b"PING late\r\n".to_vec(),
    };
    session.owner.handle(line, &session.root).await;
    assert_eq!(session.write()?.close, Some(CloseReason::Shutdown));
    Ok(())
}

#[tokio::test]
async fn a_draining_session_is_not_closed_twice_by_a_late_line() -> TestResult {
    let mut session = Session::unauthenticated()?;
    let drained = session
        .owner
        .lifecycle_outcome(AdminLifecyclePhase::Drain, &session.root)
        .await;
    assert!(matches!(drained, Ok(AdminLifecycleOutcome::Draining(_))));
    let _shutdown = session.write()?;
    let line = AdminOwnerMessage::Line {
        generation: session.generation,
        line: b"PING late\r\n".to_vec(),
    };
    session.owner.handle(line, &session.root).await;
    assert!(session.is_silent());

    let closed = AdminOwnerMessage::Closed {
        generation: session.generation,
        reason: CloseReason::Shutdown,
    };
    session.owner.handle(closed, &session.root).await;
    assert!(session.owner.sessions.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_transport_close_forgets_the_session() -> TestResult {
    let mut session = Session::unauthenticated()?;
    let closed = AdminOwnerMessage::Closed {
        generation: session.generation,
        reason: CloseReason::TransportLoss,
    };
    session.owner.handle(closed, &session.root).await;
    assert!(session.owner.sessions.is_empty());
    assert!(session.is_silent());
    Ok(())
}

#[test]
fn a_duplicate_generation_is_refused_without_replacing_the_session() -> TestResult {
    let mut session = Session::unauthenticated()?;
    let (duplicate, mut refused) = output();
    session
        .owner
        .open(session.generation, challenge(), local_peer(), duplicate);
    assert_eq!(refused.try_recv()?.close, Some(CloseReason::ProtocolError));
    assert_eq!(session.owner.sessions.len(), 1);
    assert!(session.is_silent());
    Ok(())
}

#[test]
fn an_unlisted_peer_is_refused_before_any_challenge() -> TestResult {
    let mut owner = lifecycle_owner()?;
    let (stranger, mut refused) = output();
    let peer = PeerIdentity::Local {
        uid: 2000,
        gid: 2000,
    };
    owner.open(ConnectionGeneration::new(42), challenge(), peer, stranger);
    let write = refused.try_recv()?;
    assert!(write.lines.is_empty());
    assert_eq!(write.close, Some(CloseReason::ProtocolError));
    assert!(owner.sessions.is_empty());
    Ok(())
}

#[test]
fn a_session_whose_challenge_cannot_be_queued_is_not_admitted() -> TestResult {
    let mut owner = lifecycle_owner()?;
    let (sender, mut receiver) = mpsc::channel(1);
    let full = AdminOutput::new(sender);
    full.try_line("NOTE X OK :occupied".to_owned())
        .map_err(|_| "prefill")?;
    owner.open(
        ConnectionGeneration::new(43),
        challenge(),
        local_peer(),
        full,
    );
    assert!(owner.sessions.is_empty());
    assert_eq!(
        receiver.try_recv()?.lines,
        vec![b"NOTE X OK :occupied".to_vec()]
    );
    assert!(receiver.try_recv().is_err());
    Ok(())
}

#[test]
fn a_pinned_tls_peer_is_admitted_as_a_remote_session() -> TestResult {
    let mut owner = lifecycle_owner()?;
    owner.admission = AdminAdmissionSnapshot::new(Vec::new(), Vec::new(), vec![[9; 32]]);
    let remote = AdminChallenge::new(
        AdminSessionId::from_bytes([3; 16]),
        Challenge::from_bytes([4; 32]),
        TransportKind::Tls,
        TransportBinding::from_bytes([5; 32]),
    );
    let (sender, mut receiver) = output();
    let generation = ConnectionGeneration::new(44);
    owner.open(generation, remote, PeerIdentity::Pin([9; 32]), sender);
    assert!(receiver.try_recv()?.close.is_none());
    let owned = owner.sessions.get(&generation).ok_or("session")?;
    assert_eq!(owned.purpose, ListenerPurpose::AdminTls);
    Ok(())
}

#[tokio::test]
async fn a_retention_sweep_without_configuration_is_settled() -> TestResult {
    let mut owner = lifecycle_owner()?;
    let root = CancellationToken::root();
    assert_eq!(
        owner.retention_sweep(&root).await,
        Ok(RetentionProgress::Settled)
    );
    Ok(())
}

#[tokio::test]
async fn a_retention_sweep_without_a_wall_clock_is_an_audit_failure() -> TestResult {
    let mut owner = lifecycle_owner()?;
    owner.config = Some(RuntimeConfigHandle::new(golden_snapshot("AgenC", None)?));
    owner.wall = Box::new(DeterministicWallClock::unavailable_at(0));
    let root = CancellationToken::root();
    assert_eq!(
        owner.retention_sweep(&root).await,
        Err(AdminLifecycleFailure::Audit)
    );
    Ok(())
}

#[tokio::test]
async fn a_retention_sweep_without_a_verified_source_is_an_audit_failure() -> TestResult {
    let mut owner = lifecycle_owner()?;
    owner.config = Some(RuntimeConfigHandle::new(golden_snapshot("AgenC", None)?));
    let root = CancellationToken::root();
    assert_eq!(
        owner.retention_sweep(&root).await,
        Err(AdminLifecycleFailure::Audit)
    );
    Ok(())
}

#[test]
fn reconciliation_without_configuration_keeps_the_registry() -> TestResult {
    let mut owner = lifecycle_owner()?;
    let before = owner.registry.clone();
    owner.reconcile_authority();
    assert!(owner.registry == before);
    Ok(())
}

#[test]
fn an_unchanged_registry_still_adopts_the_live_admission() -> TestResult {
    let mut session = Session::unauthenticated()?;
    let snapshot = golden_snapshot("AgenC", None)?;
    session.owner.registry = snapshot.operators().clone();
    session.owner.admission = AdminAdmissionSnapshot::new(Vec::new(), Vec::new(), Vec::new());
    session.owner.config = Some(RuntimeConfigHandle::new(snapshot));
    session.owner.reconcile_authority();
    assert!(session.owner.admission.admits(local_peer()));
    assert_eq!(session.owner.sessions.len(), 1);
    assert!(session.is_silent());
    Ok(())
}

#[tokio::test]
async fn a_replaced_registry_drops_operators_it_no_longer_lists() -> TestResult {
    let mut session = Session::authenticated().await?;
    let waiting = ConnectionGeneration::new(45);
    let (sender, mut waiting_output) = output();
    session
        .owner
        .open(waiting, challenge(), local_peer(), sender);
    let _challenge = waiting_output.try_recv()?;
    let snapshot = golden_snapshot("AgenC", None)?;
    session.owner.config = Some(RuntimeConfigHandle::new(Arc::clone(&snapshot)));

    session.owner.reconcile_authority();

    assert!(session.owner.registry == *snapshot.operators());
    assert_eq!(session.write()?.close, Some(CloseReason::ProtocolError));
    assert!(!session.owner.sessions.contains_key(&session.generation));
    assert!(session.owner.sessions.contains_key(&waiting));
    assert!(waiting_output.try_recv().is_err());
    Ok(())
}

#[tokio::test]
async fn a_closed_configuration_feed_stops_the_owner() -> TestResult {
    let mut session = Session::unauthenticated()?;
    let (feed, changes) = watch::channel(ConfigRevision::INITIAL);
    drop(feed);
    session.owner.config_changes = Some(changes);
    let (_port, inbox) = admin_transport_channel(binding());
    let (_lifecycle, lifecycle_inbox) = admin_lifecycle_channel();
    let run = session.owner.run(inbox, lifecycle_inbox, session.root);
    tokio::time::timeout(Duration::from_secs(5), run).await?;
    let close = session.output.try_recv()?;
    assert_eq!(close.close, Some(CloseReason::Shutdown));
    Ok(())
}

#[tokio::test]
async fn a_lost_lifecycle_control_is_fatal() -> TestResult {
    let mut owner = lifecycle_owner()?;
    let (fatal, mut signalled) = mpsc::channel(1);
    owner.fatal = Some(fatal);
    let (_port, inbox) = admin_transport_channel(binding());
    let (lifecycle, lifecycle_inbox) = admin_lifecycle_channel();
    drop(lifecycle);
    let run = owner.run(inbox, lifecycle_inbox, CancellationToken::root());
    tokio::time::timeout(Duration::from_secs(5), run).await?;
    signalled.try_recv()?;
    Ok(())
}

#[tokio::test]
async fn a_connection_the_owner_cannot_accept_returns_its_slot() -> TestResult {
    let (port, inbox) = admin_transport_channel(binding());
    drop(inbox);
    let listener = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
    let resources = ConnectionResources {
        permits: export_memory()?,
        global_slot: None,
        listener_slot: std::sync::Arc::clone(&listener).try_acquire_owned()?,
    };
    let (transport, _peer) = tokio::io::duplex(64);
    let generation = ConnectionGeneration::new(46);
    let start = AdminConnectionStart {
        generation,
        purpose: ListenerPurpose::AdminLocal,
        resources,
        challenge: challenge(),
        peer: local_peer(),
        port,
        token: CancellationToken::root(),
    };
    let exit = run_admin_connection(transport, start).await;
    assert_eq!(exit.reason, CloseReason::Shutdown);
    assert_eq!(exit.generation, generation);
    assert_eq!(listener.available_permits(), 1);
    Ok(())
}

#[tokio::test]
async fn a_bare_line_feed_is_a_protocol_error() {
    let (port, _inbox) = admin_transport_channel(binding());
    let reason = run_admin_reader(
        &b"\nPING x\r\n"[..],
        ConnectionGeneration::new(47),
        port,
        CancellationToken::root(),
    )
    .await;
    assert_eq!(reason, CloseReason::ProtocolError);
}

#[tokio::test]
async fn a_reader_whose_owner_is_gone_stops_as_a_shutdown() {
    let (port, inbox) = admin_transport_channel(binding());
    drop(inbox);
    let reason = run_admin_reader(
        &b"PING x\r\n"[..],
        ConnectionGeneration::new(48),
        port,
        CancellationToken::root(),
    )
    .await;
    assert_eq!(reason, CloseReason::Shutdown);
}

#[tokio::test]
async fn a_writer_whose_transport_is_gone_reports_transport_loss() -> TestResult {
    let (transport, peer) = tokio::io::duplex(64);
    drop(peer);
    let (sender, receiver) = mpsc::channel(1);
    let batch =
        AdminWrite::ordinary(vec!["NOTE X OK :lost".to_owned()], None).map_err(|_| "batch")?;
    sender.try_send(batch).map_err(|_| "queue")?;
    let acknowledgement = FlushAcknowledgement::pending();
    let reason = run_admin_writer(
        transport,
        receiver,
        CancellationToken::root(),
        acknowledgement.clone(),
    )
    .await;
    assert_eq!(reason, CloseReason::TransportLoss);
    assert!(acknowledgement.is_acknowledged());
    Ok(())
}

#[test]
fn backup_reconciliation_ignores_files_of_other_actions() -> TestResult {
    let directory = BackupTestDirectory::create()?;
    touch(&directory, "notes.txt")?;
    let other_action = format!(
        "admin-{:020}-{}.agenc-backup",
        8,
        encode_base64url(&[41; 16])
    );
    touch(&directory, &other_action)?;
    assert_eq!(
        backup_reconciliation_job(&directory, 7, 50)?.run(),
        Ok(false)
    );
    Ok(())
}

#[test]
fn backup_reconciliation_rejects_a_malformed_backup_identifier() -> TestResult {
    let directory = BackupTestDirectory::create()?;
    touch(&directory, &format!("admin-{:020}-short.agenc-backup", 7))?;
    assert_eq!(
        backup_reconciliation_job(&directory, 7, 50)?.run(),
        Err(StorageError::AuthenticationFailed)
    );
    Ok(())
}
