//! RUN-05: an edge runs the four-phase shutdown to completion inside its
//! budgets while a federated request is still unanswered and its journal
//! ownership is retained, and reopens at the prior or a successor state.
#![forbid(unsafe_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use agenc_ircd_storage::{ReadPlan, StoredKey, TableId};

use super::*;
use crate::state_core::inbox::LifecycleControl;
use crate::supervisor::{
    PhaseOutcome, ShutdownFailure, ShutdownHooks, ShutdownPhase, ShutdownPlan, run_shutdown,
};

/// A retained row: its exact key and its sealed bytes.
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

/// The physical close the connection task reports once drain has enqueued
/// the connection's final line.
struct PendingClose {
    closes: ConnectionClosePort,
    generation: ConnectionGeneration,
    final_line_sequence: u64,
}

impl PendingClose {
    fn publish(&self) -> Result<(), ShutdownFailure> {
        let budget = MemoryBudget::new(1);
        let charges = BoundedMemoryCharges::new(&[MemoryCharge::fixed(1)])
            .map_err(|_| ShutdownFailure::Writer)?;
        let mut permits = budget
            .try_acquire_batch(charges)
            .map_err(|_| ShutdownFailure::Writer)?;
        let permit = permits.split_exact(1).ok_or(ShutdownFailure::Writer)?;
        let (return_permit, _returned) = oneshot::channel();
        self.closes
            .try_reserve()
            .map_err(|()| ShutdownFailure::Writer)?
            .send(PhysicalCloseNotice {
                generation: self.generation,
                reason: CloseReason::Shutdown,
                closed_at: None,
                final_line_sequence: self.final_line_sequence,
                state_permit: ConnectionStatePermit::new(permit, return_permit),
            });
        Ok(())
    }
}

/// Drives the edge's state owner through the four phases and reports the
/// connection's physical close from the drain phase, as the daemon does.
struct EdgeHooks {
    lifecycle: LifecycleControl,
    close: Option<PendingClose>,
    stop_deadline_expired: Arc<AtomicBool>,
}

impl ShutdownHooks for EdgeHooks {
    fn run(
        &mut self,
        phase: ShutdownPhase,
        _budget: Duration,
    ) -> impl Future<Output = Result<(), ShutdownFailure>> + Send {
        let lifecycle = self.lifecycle.clone();
        let close = (phase == ShutdownPhase::Drain)
            .then(|| self.close.take())
            .flatten();
        let requested = match phase {
            ShutdownPhase::Quiesce => LifecyclePhase::Quiesce,
            ShutdownPhase::Drain => LifecyclePhase::Drain,
            ShutdownPhase::Flush => LifecyclePhase::Flush,
            ShutdownPhase::Stop => LifecyclePhase::Stop,
        };
        async move {
            if let Some(close) = close {
                close.publish()?;
            }
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

/// Reads every retained row of one table through the fixture's storage.
fn retained_rows(
    fixture: &StateCoreFixture,
    table: TableId,
    minimum: usize,
) -> TestResult<Vec<RetainedRow>> {
    let plan = ReadPlan::range(
        table,
        StoredKey::new(vec![0; minimum])?,
        StoredKey::new(vec![255; 64])?,
        4_096,
    )?;
    Ok(fixture
        .read_rows(plan)?
        .records
        .into_iter()
        .map(|record| (record.key, record.sealed_record))
        .collect())
}

/// The retained origin ownership and request results the stop must preserve.
fn retained_recovery_state(fixture: &StateCoreFixture) -> TestResult<Vec<RetainedRow>> {
    let mut rows = retained_rows(fixture, TableId::FederationOrigin, 56)?;
    rows.extend(retained_rows(fixture, TableId::RequestResult, 16)?);
    Ok(rows)
}

/// Every row the stop observed must reappear byte for byte.
fn reopened_retains_every_row(before: &[RetainedRow], after: &[RetainedRow]) -> TestResult {
    for (key, sealed) in before {
        let found = after
            .iter()
            .find(|(reopened, _)| reopened == key)
            .ok_or("a retained recovery row vanished across the reopen")?;
        if &found.1 != sealed {
            return Err("a retained recovery row changed across the reopen".into());
        }
    }
    Ok(())
}

/// Registers `quinn` through the coordinator and returns the client.
async fn register_through_hub(
    hub: &mut Hub,
    inbox: mpsc::Sender<StateCoreMessage>,
) -> TestResult<Client> {
    hub.establish().await?;
    hub.synchronize().await?;
    let mut client = Client::open(inbox, 1).await?;
    hub.ack_origin().await?;
    client.line("NICK quinn").await?;
    client.line("USER quinn 0 * :Quinn Real").await?;
    let (header, operation, bytes) = hub.next_request().await?;
    if !matches!(operation, FederatedOperation::SessionOpen { .. }) {
        return Err("expected session_open".into());
    }
    let session_id = SessionId::from_bytes([61; 16]);
    let user_id = UserId::from_bytes([62; 16]);
    hub.state_generation += 1;
    let generation = hub.state_generation;
    answer_session_open(hub, &header, &bytes, session_id, user_id, generation).await?;
    client.wait_for(" 001 quinn ").await?;
    hub.ack_origin().await?;
    Ok(client)
}

/// Delivers the visible event, its completion and the committed result.
async fn answer_session_open(
    hub: &mut Hub,
    header: &RequestHeader,
    bytes: &[u8],
    session_id: SessionId,
    user_id: UserId,
    generation: u64,
) -> TestResult {
    let _visible = hub
        .event(
            &ProjectedEvent::SessionVisible(SessionEventView {
                source: source(user_id, "quinn", 1)?,
                home_projection: Some(session_record(session_id, user_id, "quinn", generation, 1)?),
            }),
            None,
        )
        .await?;
    let completion = hub
        .event(
            &ProjectedEvent::RequestCompleted {
                resulting_state_generation: generation,
            },
            Some(RequestCorrelation {
                replay_key: header.replay_key,
                request_id: header.request_id,
            }),
        )
        .await?;
    hub.result(
        header,
        bytes,
        &ResultArm::SessionRegistered(SessionRegistered {
            session_id,
            user_id,
            session_revision: generation,
            account: None,
            resulting_state_generation: generation,
        }),
        Vec::new(),
        Some(completion),
    )
    .await
}

#[tokio::test]
async fn an_edge_stops_inside_its_budgets_with_an_unanswered_federated_request() -> TestResult {
    let mut fixture = StateCoreFixture::with_edge(entropy_script(), coordinator_identity())?;
    let mut parts = fixture.take_run_parts()?;
    let (inbox, inbox_receiver) = mpsc::channel(8);
    let (federation, federation_receiver) = mpsc::channel(64);
    parts.state.install_federation_inbox(federation_receiver)?;
    let (close_port, close_inbox) = connection_close_channel();
    let (lifecycle, lifecycle_receiver) = lifecycle_channel();
    let storage = &fixture;
    let driven = drive_edge_stop(federation, inbox, close_port, lifecycle, storage);
    let run = parts.state.run(
        inbox_receiver,
        close_inbox,
        lifecycle_receiver,
        parts.storage,
        parts.storage_reads,
        parts.checkpoints,
        parts.crypto,
        crate::cancel::CancellationToken::root(),
    );
    let (exit, driver) = tokio::join!(run, driven);
    let retained = driver?;
    assert!(matches!(exit, StateCoreExit::Stopped), "{exit:?}");
    assert!(
        !parts.state.context().sessions().has_physical_connections(),
        "the stop stranded a physical session"
    );
    let (bridge, crypto) = parts.state.into_bridges();
    drop((bridge, crypto));
    fixture.restart_registration_storage(entropy_script())?;
    let reopened = retained_recovery_state(&fixture)?;
    assert!(!reopened.is_empty(), "the reopened edge retained nothing");
    reopened_retains_every_row(&retained, &reopened)
}

/// Leaves one federated request unanswered with the link lost, proves the
/// client never saw a reply, and then runs the real four-phase driver.
async fn drive_edge_stop(
    federation: mpsc::Sender<FederationInbound>,
    inbox: mpsc::Sender<StateCoreMessage>,
    closes: ConnectionClosePort,
    lifecycle: LifecycleControl,
    fixture: &StateCoreFixture,
) -> TestResult<Vec<RetainedRow>> {
    let mut hub = Hub::new(federation);
    let mut client = register_through_hub(&mut hub, inbox.clone()).await?;
    client.line("JOIN #recovery").await?;
    let (_header, operation, _bytes) = hub.next_request().await?;
    if !matches!(operation, FederatedOperation::Join { .. }) {
        return Err("expected the join request".into());
    }
    // The coordinator never answers and the link is lost, so the edge keeps
    // its retained request and arms its journal recovery.
    hub.send(LinkEvent::Closed(
        crate::federation::LinkCloseReason::PeerClosed,
    ))
    .await?;
    let retained = retained_recovery_state(fixture)?;
    assert!(
        !retained.is_empty(),
        "no durable recovery state was outstanding, so this stop proves nothing"
    );
    assert!(
        !client
            .sink
            .lines()
            .iter()
            .any(|line| line.contains(" JOIN ")),
        "the edge answered a request its coordinator never committed"
    );
    run_bounded_edge_stop(lifecycle, closes, &client).await?;
    drop(inbox);
    Ok(retained)
}

/// Runs the four phases and requires each one inside its own budget.
async fn run_bounded_edge_stop(
    lifecycle: LifecycleControl,
    closes: ConnectionClosePort,
    client: &Client,
) -> TestResult {
    let plan = tightened_plan()?;
    let expired = Arc::new(AtomicBool::new(false));
    let mut hooks = EdgeHooks {
        lifecycle,
        close: Some(PendingClose {
            closes,
            generation: client.generation,
            final_line_sequence: client.sequence,
        }),
        stop_deadline_expired: Arc::clone(&expired),
    };
    let (_signals, mut signal_receiver) = mpsc::channel(4);
    let started = tokio::time::Instant::now();
    let report = run_shutdown(plan, &mut hooks, &mut signal_receiver).await;
    assert!(
        started.elapsed() <= plan.total(),
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
    Ok(())
}
