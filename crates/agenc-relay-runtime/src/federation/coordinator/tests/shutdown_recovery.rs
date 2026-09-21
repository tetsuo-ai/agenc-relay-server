//! RUN-05: the four-phase shutdown runs to completion inside its budgets
//! while federation recovery is live and acknowledgement work is still
//! outstanding, and the reopened database holds the prior or a successor
//! state. No test here drains the network first.
#![forbid(unsafe_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use agenc_relay_storage::federation_records::parse_outbox_key;
use agenc_relay_storage::{ReadPlan, StoredKey, TableId};
use tokio::sync::oneshot;

use super::*;
use crate::bridge::StorageCompletionMessage;
use crate::state_core::inbox::LifecycleControl;
use crate::supervisor::{
    PhaseOutcome, ShutdownFailure, ShutdownHooks, ShutdownPhase, ShutdownPlan, run_shutdown,
};

/// How long a probe waits before concluding that nothing is coming.
const PROBE: Duration = Duration::from_millis(200);

/// A retained outbox row: its exact key and its sealed bytes.
type RetainedRow = (StoredKey, Vec<u8>);

/// Tightened budgets: every phase below is a fraction of the spec defaults,
/// so a run that completes here also completes inside the configured plan.
fn tightened_plan() -> TestResult<ShutdownPlan> {
    Ok(ShutdownPlan::new(
        Duration::from_secs(2),
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(2),
    )?)
}

/// Drives one state owner through the four phases exactly as the daemon's
/// runtime hooks do, and records whether the absolute stop deadline expired.
struct LifecycleHooks {
    lifecycle: LifecycleControl,
    stop_deadline_expired: Arc<AtomicBool>,
}

impl ShutdownHooks for LifecycleHooks {
    fn run(
        &mut self,
        phase: ShutdownPhase,
        _budget: Duration,
    ) -> impl Future<Output = Result<(), ShutdownFailure>> + Send {
        let lifecycle = self.lifecycle.clone();
        let requested = match phase {
            ShutdownPhase::Quiesce => LifecyclePhase::Quiesce,
            ShutdownPhase::Drain => LifecyclePhase::Drain,
            ShutdownPhase::Flush => LifecyclePhase::Flush,
            ShutdownPhase::Stop => LifecyclePhase::Stop,
        };
        async move {
            lifecycle
                .request(requested)
                .await
                .map_err(|_| ShutdownFailure::StateCore)
        }
    }

    fn stop_deadline_expired(&mut self) {
        self.stop_deadline_expired.store(true, Ordering::Release);
    }
}

/// Reads every retained delivery the coordinator still owes one edge.
fn retained_outbox(fixture: &StateCoreFixture) -> TestResult<Vec<RetainedRow>> {
    let plan = ReadPlan::range(
        TableId::EdgeOutbox,
        StoredKey::new(vec![0; 32])?,
        StoredKey::new(vec![255; 32])?,
        4_096,
    )?;
    let result = fixture.read_rows(plan)?;
    Ok(result
        .records
        .into_iter()
        .map(|record| (record.key, record.sealed_record))
        .collect())
}

/// Every row the stop observed must reappear byte for byte, and the reopened
/// delivery sequences must stay strictly ordered, so nothing was lost and no
/// sequence was reused.
fn reopened_retains_every_row(before: &[RetainedRow], after: &[RetainedRow]) -> TestResult {
    for (key, sealed) in before {
        let found = after
            .iter()
            .find(|(reopened, _)| reopened == key)
            .ok_or("a retained delivery vanished across the reopen")?;
        if &found.1 != sealed {
            return Err("a retained delivery changed across the reopen".into());
        }
    }
    let mut last = None;
    for (key, _) in after {
        let parts = parse_outbox_key(key)?;
        let position = (
            parts.target,
            parts.projection_generation,
            parts.delivery_sequence,
        );
        if last.is_some_and(|previous| previous >= position) {
            return Err("the reopened outbox reused a delivery sequence".into());
        }
        last = Some(position);
    }
    Ok(())
}

/// Starts an unfinished OPAQUE exchange on `edge`: the coordinator answers
/// the challenge and the client never sends its finish, so the virtual
/// account carrier is still live and holding durable transaction state.
async fn unfinished_account_exchange(edge: &mut Edge, origin: &mut Origin) -> TestResult {
    let envelope = crate::test_support::sealed_authentication_start(
        NETWORK,
        RecoveryEpoch::from_bytes([34; 16]),
        "absent-account",
        171,
    )?;
    let mut budget = DecodeBudget::new(8_192, 64);
    let envelope = SchemaObject::decode_exact("AccountServiceEnvelope", &envelope, &mut budget)?;
    request(
        edge,
        origin,
        &FederatedOperation::AccountService {
            opcode: agenc_relay_types::FederationOpcode::OpaqueAuthStart,
            session_id: None,
            envelope,
        },
    )
    .await?;
    let challenge = answer(edge, &mut Vec::new()).await?;
    if !matches!(challenge.arm, ResultArm::AuthChallenge(_)) {
        return Err("the coordinator refused the scripted challenge".into());
    }
    origin.sequence += 1;
    Ok(())
}

/// Leaves `away` mid-recovery: it resumes from its retained cursor and the
/// coordinator replies FRESUME OK, but the origin replay never finishes, so
/// the peer is inside its recovery transition when the stop arrives.
async fn hold_recovery_open(away: &mut Edge) -> TestResult {
    let cursor = match away.last_ack {
        Some((delivery_sequence, event_id)) => agenc_relay_federation_wire::DeliveryCursor::At {
            delivery_sequence,
            event_id,
        },
        None => agenc_relay_federation_wire::DeliveryCursor::Empty,
    };
    away.establish().await?;
    away.frame(FederationFrame::Resume {
        coordinator_server_id: COORDINATOR,
        projection_generation: away.projection_generation,
        cursor,
    })
    .await?;
    match away.next_wire_frame().await? {
        FederationFrame::ResumeOk { .. } => Ok(()),
        other => Err(format!("expected FRESUME OK, got {:?}", other.kind()).into()),
    }
}

/// Builds the outstanding recovery state: a reserved delivery for the edge
/// that is away, that edge back inside an unfinished recovery, and an
/// abandoned account carrier on the edge that stayed.
async fn stage_outstanding_recovery(
    away: &mut Edge,
    away_origin: &mut Origin,
    live: &mut Edge,
    live_origin: &mut Origin,
) -> TestResult {
    for (edge, origin) in [
        (&mut *away, &mut *away_origin),
        (&mut *live, &mut *live_origin),
    ] {
        edge.establish().await?;
        synchronize_ok(edge, &mut [origin]).await?;
    }
    let mut events = Vec::new();
    let (away_session, _, away_revision) =
        open_session(away, away_origin, "ada", &mut events).await?;
    let (live_session, _, live_revision) =
        open_session(live, live_origin, "bo", &mut events).await?;
    join_channel(away, away_origin, away_session, away_revision, "#recovery").await?;
    away.close().await?;
    // Every change made while the edge is away is reserved, not delivered.
    let channel = join_channel(live, live_origin, live_session, live_revision, "#recovery").await?;
    for body in ["first", "second"] {
        say(live, live_origin, live_session, channel, body).await?;
    }
    unfinished_account_exchange(live, live_origin).await?;
    hold_recovery_open(away).await
}

/// Sends one channel message whose delivery the absent edge never receives.
async fn say(
    edge: &mut Edge,
    origin: &mut Origin,
    session_id: SessionId,
    channel_id: agenc_relay_types::ChannelInstanceId,
    body: &str,
) -> TestResult {
    let expected_revision = *edge
        .channel_revisions
        .get(&channel_id)
        .ok_or("the speaker never learned the channel revision")?;
    request(
        edge,
        origin,
        &FederatedOperation::Message {
            session_id,
            kind: agenc_relay_domain::MessageKind::Privmsg,
            targets: vec![MessageTargetArg::Channel {
                channel_id,
                expected_revision,
            }],
            tags: Vec::new(),
            body: body.to_owned(),
        },
    )
    .await?;
    let spoke = answer(edge, &mut Vec::new()).await?;
    origin.sequence += 1;
    if spoke.header.result_kind != FederationResultKind::Committed {
        return Err("the scripted message was not committed".into());
    }
    Ok(())
}

#[tokio::test]
async fn a_four_phase_stop_completes_inside_its_budgets_while_recovery_is_outstanding() -> TestResult
{
    let away_peer = peer_identity(ServerId::from_bytes([60; 16]), "edge-away.example");
    let live_peer = peer_identity(ServerId::from_bytes([61; 16]), "edge-live.example");
    let mut fixture = StateCoreFixture::with_federation_coordinator(
        entropy_script(),
        vec![away_peer, live_peer],
    )?;
    let mut parts = fixture.take_run_parts()?;
    let (inbox, inbox_receiver) = mpsc::channel(8);
    let (federation, federation_receiver) = mpsc::channel(64);
    parts.state.install_federation_inbox(federation_receiver)?;
    let (_close_port, close_inbox) = connection_close_channel();
    let (lifecycle, lifecycle_receiver) = lifecycle_channel();
    let storage = &fixture;
    let driven = async move {
        let result = drive_bounded_stop(&federation, storage, lifecycle).await;
        drop(inbox);
        result
    };
    let run = parts.state.run(
        inbox_receiver,
        close_inbox,
        lifecycle_receiver,
        parts.storage,
        parts.storage_reads,
        parts.checkpoints,
        parts.crypto,
        CancellationToken::root(),
    );
    let (exit, driver) = tokio::join!(run, driven);
    let retained = driver?;
    assert!(matches!(exit, StateCoreExit::Stopped), "{exit:?}");
    assert_eq!(
        parts.state.context().sessions().len(),
        0,
        "the stop stranded a virtual account carrier"
    );
    assert_eq!(
        parts.state.context().head().account_service_response_count,
        1,
        "the stop invented an account-service response"
    );
    let (bridge, crypto) = parts.state.into_bridges();
    drop((bridge, crypto));
    reopen_and_compare(&mut fixture, &retained).await
}

/// Reopens the sealed database and requires the prior or a successor state.
async fn reopen_and_compare(
    fixture: &mut StateCoreFixture,
    retained: &[RetainedRow],
) -> TestResult {
    fixture.restart_registration_storage(entropy_script())?;
    let reopened = retained_outbox(fixture)?;
    assert!(
        !reopened.is_empty(),
        "the reopened database retained no delivery"
    );
    reopened_retains_every_row(retained, &reopened)?;
    let transactions = fixture.read_rows(ReadPlan::range(
        TableId::AuthTransaction,
        StoredKey::new(vec![0; 16])?,
        StoredKey::new(vec![255; 16])?,
        10,
    )?)?;
    assert!(
        transactions.records.is_empty(),
        "the abandoned carrier left a durable authentication transaction"
    );
    Ok(())
}

/// Stages the outstanding recovery, proves it is live, then runs the real
/// four-phase driver and returns the deliveries the stop observed.
async fn drive_bounded_stop(
    inbox: &mpsc::Sender<FederationInbound>,
    fixture: &StateCoreFixture,
    lifecycle: LifecycleControl,
) -> TestResult<Vec<RetainedRow>> {
    let mut away = Edge::new(inbox.clone(), 60);
    let mut live = Edge::new(inbox.clone(), 61);
    let mut away_origin = Origin::new(160);
    let mut live_origin = Origin::new(161);
    stage_outstanding_recovery(&mut away, &mut away_origin, &mut live, &mut live_origin).await?;
    let retained = retained_outbox(fixture)?;
    // The scripted member_joined and both messages are still unacknowledged.
    assert!(
        retained.len() >= 3,
        "only {} deliveries were outstanding, so this stop proves nothing",
        retained.len()
    );
    let plan = tightened_plan()?;
    let expired = Arc::new(AtomicBool::new(false));
    let mut hooks = LifecycleHooks {
        lifecycle,
        stop_deadline_expired: Arc::clone(&expired),
    };
    let (_signals, mut signal_receiver) = mpsc::channel(4);
    let started = tokio::time::Instant::now();
    let report = run_shutdown(plan, &mut hooks, &mut signal_receiver).await;
    let elapsed = started.elapsed();
    assert!(
        elapsed <= plan.total(),
        "the stop exceeded its total budget"
    );
    assert!(
        !expired.load(Ordering::Acquire),
        "the stop deadline expired"
    );
    assert_eq!(report.first_problem(), None, "{report:?}");
    for phase in ShutdownPhase::ALL {
        assert_eq!(report.outcome(phase), PhaseOutcome::Completed, "{report:?}");
    }
    Ok(retained)
}

/// Buffers every commit receipt while `armed`, so a committed storage
/// outcome stays without its index readback and publication, and releases
/// the buffer in order when the driver fires `release`.
async fn hold_receipts_when_armed(
    mut input: mpsc::Receiver<StorageCompletionMessage>,
    output: mpsc::Sender<StorageCompletionMessage>,
    armed: Arc<AtomicBool>,
    mut release: oneshot::Receiver<()>,
    held: Arc<AtomicUsize>,
) {
    let mut queued = Vec::new();
    let mut gated = true;
    loop {
        let message = tokio::select! {
            message = input.recv() => message,
            _ = &mut release, if gated => {
                gated = false;
                armed.store(false, Ordering::SeqCst);
                for message in queued.drain(..) {
                    if output.send(message).await.is_err() {
                        return;
                    }
                }
                continue;
            }
        };
        let Some(message) = message else { return };
        if armed.load(Ordering::SeqCst) {
            held.fetch_add(1, Ordering::SeqCst);
            queued.push(message);
        } else if output.send(message).await.is_err() {
            return;
        }
    }
}

/// Waits for the relay to buffer at least one receipt without a wall-clock
/// deadline of its own: the actor cannot progress until the relay forwards.
async fn wait_for_held_receipt(held: &AtomicUsize) -> TestResult {
    for _ in 0..5_000 {
        if held.load(Ordering::SeqCst) != 0 {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    Err("no commit receipt was withheld".into())
}

#[tokio::test]
async fn drain_waits_for_a_committed_outcome_that_still_owes_its_readback() -> TestResult {
    let peer = peer_identity(ServerId::from_bytes([62; 16]), "edge-readback.example");
    let mut fixture = StateCoreFixture::with_federation_coordinator(entropy_script(), vec![peer])?;
    let mut parts = fixture.take_run_parts()?;
    let (inbox, inbox_receiver) = mpsc::channel(8);
    let (federation, federation_receiver) = mpsc::channel(64);
    parts.state.install_federation_inbox(federation_receiver)?;
    let (_close_port, close_inbox) = connection_close_channel();
    let (lifecycle, lifecycle_receiver) = lifecycle_channel();
    let (storage_sender, storage_receiver) = mpsc::channel(8);
    let armed = Arc::new(AtomicBool::new(false));
    let held = Arc::new(AtomicUsize::new(0));
    let (release, released) = oneshot::channel();
    // The relay outlives the actor's own exit, so it is owned by a task the
    // test cancels rather than by the join below.
    let relay = tokio::spawn(hold_receipts_when_armed(
        parts.storage,
        storage_sender,
        Arc::clone(&armed),
        released,
        Arc::clone(&held),
    ));
    let driven = async move {
        let result = drive_held_readback(&federation, lifecycle, &armed, &held, release).await;
        drop(inbox);
        result
    };
    let run = parts.state.run(
        inbox_receiver,
        close_inbox,
        lifecycle_receiver,
        storage_receiver,
        parts.storage_reads,
        parts.checkpoints,
        parts.crypto,
        CancellationToken::root(),
    );
    let (exit, driver) = tokio::join!(run, driven);
    relay.abort();
    driver?;
    assert!(matches!(exit, StateCoreExit::Stopped), "{exit:?}");
    Ok(())
}

/// Requests drain while a committed outcome is still buffered, proves that
/// neither the result nor the phase is acknowledged, releases the receipt
/// and requires both to arrive only afterwards.
async fn drive_held_readback(
    inbox: &mpsc::Sender<FederationInbound>,
    lifecycle: LifecycleControl,
    armed: &AtomicBool,
    held: &AtomicUsize,
    release: oneshot::Sender<()>,
) -> TestResult {
    let mut edge = Edge::new(inbox.clone(), 62);
    let mut origin = Origin::new(162);
    edge.establish().await?;
    synchronize_ok(&mut edge, &mut [&mut origin]).await?;
    armed.store(true, Ordering::SeqCst);
    request(&mut edge, &mut origin, &session_open(162, "cyd")).await?;
    wait_for_held_receipt(held).await?;
    assert!(
        tokio::time::timeout(PROBE, edge.next_wire_frame())
            .await
            .is_err(),
        "the coordinator answered before its matching durable receipt"
    );
    lifecycle
        .request(LifecyclePhase::Quiesce)
        .await
        .map_err(|failure| format!("quiesce: {failure:?}"))?;
    let mut draining = Box::pin(lifecycle.request(LifecyclePhase::Drain));
    assert!(
        tokio::time::timeout(PROBE, &mut draining).await.is_err(),
        "drain acknowledged while a committed outcome owed its readback"
    );
    release.send(()).map_err(|()| "release")?;
    tokio::time::timeout(Duration::from_secs(5), &mut draining)
        .await?
        .map_err(|failure| format!("drain: {failure:?}"))?;
    drop(draining);
    let answered = answer(&mut edge, &mut Vec::new()).await?;
    assert!(
        matches!(answered.arm, ResultArm::SessionRegistered(_)),
        "the released receipt must carry the committed result, got {:?}",
        answered.header.result_kind
    );
    finish_phases(&lifecycle).await
}

/// Completes the remaining phases under the tightened flush and stop budgets.
async fn finish_phases(lifecycle: &LifecycleControl) -> TestResult {
    let plan = tightened_plan()?;
    for (phase, budget) in [
        (LifecyclePhase::Flush, plan.budget(ShutdownPhase::Flush)),
        (LifecyclePhase::Stop, plan.budget(ShutdownPhase::Stop)),
    ] {
        tokio::time::timeout(budget, lifecycle.request(phase))
            .await
            .map_err(|_| format!("{phase:?} exceeded its budget"))?
            .map_err(|failure| format!("{phase:?}: {failure:?}"))?;
    }
    Ok(())
}
