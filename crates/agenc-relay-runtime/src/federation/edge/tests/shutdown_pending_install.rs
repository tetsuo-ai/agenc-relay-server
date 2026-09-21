//! RUN-11 (issue #178): an edge with a snapshot install outstanding runs the
//! four-phase shutdown to completion inside its budgets whatever its
//! coordinator does, and reopens to a state that negotiates the snapshot
//! again. The stages that wait on the coordinator are abandoned; the stages
//! that are a local durable commit finish first.
#![forbid(unsafe_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use agenc_relay_domain::federation::ProjectionRecord;
use agenc_relay_federation_wire::{
    DeliveryCursor, FederationHash32, ProjectionEntryHeader, SnapshotIdentity, snapshot_digest,
};

use super::shutdown_recovery::{EdgeHooks, tightened_plan};
use super::*;
use crate::bridge::StorageCompletionMessage;
use crate::state_core::inbox::LifecycleControl;
use crate::supervisor::{PhaseOutcome, ShutdownPhase, ShutdownReport, run_shutdown};

/// The incarnation `Hub::establish` presents.
const LINK_INCARNATION: ServerIncarnation = ServerIncarnation::from_bytes([92; 16]);
/// The generation every scripted snapshot installs over the initial one.
const SNAPSHOT_GENERATION: u64 = 2;
/// More rows than one install batch of 256, so the install has a second
/// batch left when the first one settles.
const TWO_BATCH_ENTRIES: u16 = 300;
/// How long a phase that must wait is observed still waiting.
const HELD: Duration = Duration::from_millis(300);

/// Holds storage commit receipts back while armed, so a staged commit stays
/// in flight until the test releases it.
struct ReceiptGate {
    armed: Arc<AtomicBool>,
    held: Arc<AtomicUsize>,
    release: Option<oneshot::Sender<()>>,
}

impl ReceiptGate {
    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }

    async fn wait_for_held_receipt(&self) -> TestResult {
        for _ in 0..5_000 {
            if self.held.load(Ordering::SeqCst) != 0 {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        Err("no commit receipt was withheld".into())
    }

    fn release(&mut self) -> TestResult {
        self.release
            .take()
            .ok_or("receipt gate already released")?
            .send(())
            .map_err(|()| "receipt relay ended".into())
    }
}

async fn relay_receipts(
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

/// What a scenario drives: the scripted coordinator, the lifecycle control
/// of the running state owner, and the receipt gate.
struct Scene {
    hub: Hub,
    lifecycle: LifecycleControl,
    gate: ReceiptGate,
}

impl Scene {
    /// Links, answers FRESUME with a snapshot, and opens one of `count`
    /// entries.
    async fn open_snapshot(&mut self, ids: &[FederationHash32]) -> TestResult<SnapshotIdentity> {
        self.hub.establish().await?;
        self.hub
            .expect_frame(|frame, _| matches!(frame, FederationFrame::Resume { .. }))
            .await?;
        self.hub
            .frame(FederationFrame::ResumeSnapshot {
                edge_server_id: EDGE,
            })
            .await?;
        let identity = SnapshotIdentity {
            snapshot_token: FederationHash32::from_bytes([87; 32]),
            recovery_epoch: COORDINATOR_EPOCH,
            projection_generation: SNAPSHOT_GENERATION,
            state_generation: 10,
            snapshot_digest: snapshot_digest(&COORDINATOR_EPOCH, SNAPSHOT_GENERATION, 10, ids)?,
        };
        self.hub
            .frame(FederationFrame::SnapshotBegin {
                edge_server_id: EDGE,
                identity,
                entry_count: u64::try_from(ids.len())?,
            })
            .await?;
        Ok(identity)
    }

    async fn end_snapshot(&mut self, identity: SnapshotIdentity) -> TestResult {
        self.hub
            .frame(FederationFrame::SnapshotEnd {
                edge_server_id: EDGE,
                snapshot_token: identity.snapshot_token,
                cursor: DeliveryCursor::Empty,
            })
            .await
    }

    /// Installs an empty snapshot and waits for the edge's durable READY.
    async fn reach_ready(&mut self) -> TestResult<SnapshotIdentity> {
        let identity = self.open_snapshot(&[]).await?;
        self.end_snapshot(identity).await?;
        self.hub
            .expect_frame(|frame, _| matches!(frame, FederationFrame::SnapshotReady { .. }))
            .await?;
        Ok(identity)
    }

    /// Runs the real four-phase driver under the tightened plan.
    async fn stop(&self) -> TestResult<ShutdownReport> {
        let plan = tightened_plan()?;
        let expired = Arc::new(AtomicBool::new(false));
        let mut hooks = EdgeHooks {
            lifecycle: self.lifecycle.clone(),
            close: None,
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
        Ok(report)
    }

    /// Runs the stop, requires it to be still waiting while the staged
    /// commit's receipt is held, and releases the receipt.
    async fn stop_behind_held_receipt(&mut self) -> TestResult<ShutdownReport> {
        self.gate.wait_for_held_receipt().await?;
        let plan = tightened_plan()?;
        let mut hooks = EdgeHooks {
            lifecycle: self.lifecycle.clone(),
            close: None,
            stop_deadline_expired: Arc::new(AtomicBool::new(false)),
        };
        let (_signals, mut signal_receiver) = mpsc::channel(4);
        let stop = run_shutdown(plan, &mut hooks, &mut signal_receiver);
        tokio::pin!(stop);
        assert!(
            tokio::time::timeout(HELD, &mut stop).await.is_err(),
            "the stop completed ahead of a staged local commit"
        );
        self.gate.release()?;
        Ok(stop.await)
    }
}

fn require_clean(report: &ShutdownReport) {
    assert_eq!(report.first_problem(), None, "{report:?}");
    for phase in ShutdownPhase::ALL {
        assert_eq!(report.outcome(phase), PhaseOutcome::Completed, "{report:?}");
    }
}

/// Runs the production edge actor against `scenario`, requires a clean
/// exit, reopens the same storage and returns the edge restored from it.
async fn stop_and_reopen<S, F>(scenario: S) -> TestResult<(StateCoreFixture, EdgeFederation)>
where
    S: FnOnce(Scene) -> F,
    F: Future<Output = TestResult>,
{
    let mut fixture = StateCoreFixture::with_edge(entropy_script(), coordinator_identity())?;
    let mut parts = fixture.take_run_parts()?;
    let (inbox, inbox_receiver) = mpsc::channel::<StateCoreMessage>(8);
    let (federation, federation_receiver) = mpsc::channel(1_024);
    parts.state.install_federation_inbox(federation_receiver)?;
    let (_close_port, close_inbox) = connection_close_channel();
    let (lifecycle, lifecycle_receiver) = lifecycle_channel();
    let (storage_sender, storage_receiver) = mpsc::channel(8);
    let armed = Arc::new(AtomicBool::new(false));
    let held = Arc::new(AtomicUsize::new(0));
    let (release, released) = oneshot::channel();
    let relay = tokio::spawn(relay_receipts(
        parts.storage,
        storage_sender,
        Arc::clone(&armed),
        released,
        Arc::clone(&held),
    ));
    let scene = Scene {
        hub: Hub::new(federation),
        lifecycle,
        gate: ReceiptGate {
            armed,
            held,
            release: Some(release),
        },
    };
    let driven = async move {
        let result = scenario(scene).await;
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
        crate::cancel::CancellationToken::root(),
    );
    let (exit, driver) = tokio::join!(run, driven);
    relay.abort();
    driver?;
    assert!(matches!(exit, StateCoreExit::Stopped), "{exit:?}");
    let (bridge, crypto) = parts.state.into_bridges();
    drop((bridge, crypto));
    fixture.restart_registration_storage(entropy_script())?;
    let mut restored = resync_edge();
    fixture.restore_edge_state(&mut restored, None)?;
    Ok((fixture, restored))
}

/// Gives the restored edge a fresh link to the same coordinator incarnation
/// and returns the first frame it sends.
async fn first_frame_on_a_new_link(
    fixture: &mut StateCoreFixture,
    edge: &mut EdgeFederation,
) -> TestResult<FederationFrame> {
    let (handle, mut queue) = link_queue(1 << 20);
    edge.live = Some(LiveLink {
        link: LinkId::new(7),
        handle,
        coordinator_epoch: COORDINATOR_EPOCH,
        coordinator_incarnation: LINK_INCARNATION,
    });
    sync::begin(edge, fixture.context_mut()?);
    let line = tokio::time::timeout(Duration::from_secs(5), queue.recv())
        .await?
        .ok_or("the reopened edge sent nothing")?;
    parse_frame(line.as_str().trim_end_matches("\r\n"), EDGE_NAME)
        .map_err(|error| format!("{error:?}").into())
}

/// The reopened edge still stands on its initial generation and asks its
/// coordinator to resume, which is how an abandoned install is requested
/// again.
async fn requires_a_fresh_resume(
    fixture: &mut StateCoreFixture,
    edge: &mut EdgeFederation,
) -> TestResult {
    assert!(!sync::has_durable_ready(edge));
    assert_eq!(sync::pending_generation(edge), None);
    assert!(edge.replica.projection_generation() < SNAPSHOT_GENERATION);
    let frame = first_frame_on_a_new_link(fixture, edge).await?;
    assert!(
        matches!(frame, FederationFrame::Resume { .. }),
        "the reopened edge must ask to resume"
    );
    Ok(())
}

/// The reopened edge restored the marked pending generation and sends READY
/// for the same identity again.
async fn requires_a_replayed_ready(
    fixture: &mut StateCoreFixture,
    edge: &mut EdgeFederation,
    identity: SnapshotIdentity,
) -> TestResult {
    assert!(sync::has_durable_ready(edge));
    assert_eq!(sync::pending_generation(edge), Some(SNAPSHOT_GENERATION));
    assert!(edge.replica.projection_generation() < SNAPSHOT_GENERATION);
    let frame = first_frame_on_a_new_link(fixture, edge).await?;
    assert!(
        matches!(frame, FederationFrame::SnapshotReady { identity: replayed, .. } if replayed == identity),
        "the reopened edge must replay READY for the same identity"
    );
    Ok(())
}

async fn ready_sent_stop(link_lost: bool) -> TestResult {
    let sent = Arc::new(std::sync::Mutex::new(None));
    let recorded = Arc::clone(&sent);
    let (mut fixture, mut edge) = stop_and_reopen(|mut scene| async move {
        let identity = scene.reach_ready().await?;
        if link_lost {
            scene
                .hub
                .send(LinkEvent::Closed(
                    crate::federation::LinkCloseReason::PeerClosed,
                ))
                .await?;
        }
        // ACTIVE never arrives: the coordinator is gone or silent.
        require_clean(&scene.stop().await?);
        *recorded.lock().map_err(|_| "identity lock")? = Some(identity);
        Ok(())
    })
    .await?;
    let identity = sent
        .lock()
        .map_err(|_| "identity lock")?
        .take()
        .ok_or("the scenario recorded no identity")?;
    requires_a_replayed_ready(&mut fixture, &mut edge, identity).await
}

#[tokio::test]
async fn a_ready_sent_install_with_a_dead_coordinator_stops_clean_and_replays_ready() -> TestResult
{
    ready_sent_stop(true).await
}

#[tokio::test]
async fn a_ready_sent_install_with_a_silent_coordinator_stops_clean_and_replays_ready() -> TestResult
{
    ready_sent_stop(false).await
}

#[tokio::test]
async fn a_receiving_install_is_abandoned_and_the_reopened_edge_resumes() -> TestResult {
    let (mut fixture, mut edge) = stop_and_reopen(|mut scene| async move {
        // Two entries are announced and none is ever sent.
        let ids = [
            FederationHash32::from_bytes([1; 32]),
            FederationHash32::from_bytes([2; 32]),
        ];
        let _identity = scene.open_snapshot(&ids).await?;
        require_clean(&scene.stop().await?);
        Ok(())
    })
    .await?;
    requires_a_fresh_resume(&mut fixture, &mut edge).await
}

/// `count` local sessions in strict key order with their canonical
/// snapshot entry objects. A session is the one projection record the
/// closed snapshot entitlement admits standing alone.
fn session_entries(count: u16) -> TestResult<Vec<Vec<u8>>> {
    let mut records = Vec::new();
    for index in 0..count {
        let mut id = [0_u8; 16];
        let [high, low] = index.to_be_bytes();
        id[0] = high.saturating_add(1);
        id[1] = low;
        records.push(ProjectionRecord::Session(session_record(
            SessionId::from_bytes(id),
            UserId::from_bytes(id),
            &format!("install{index}"),
            1,
            low,
        )?));
    }
    records.sort_by_key(ProjectionRecord::key);
    records
        .iter()
        .map(|record| {
            let arm = crate::federation::codec::projection::projection_arm_object(record)?;
            let entry = ProjectionEntryHeader {
                network_id: NETWORK,
                target_server_id: EDGE,
                projection_generation: SNAPSHOT_GENERATION,
                projection_kind: crate::federation::codec::projection::projection_kind(record),
            }
            .build(&arm)?;
            Ok(entry.encode_canonical()?.as_slice().to_vec())
        })
        .collect()
}

#[tokio::test]
async fn a_staged_install_batch_settles_and_the_rest_of_the_install_is_abandoned() -> TestResult {
    let (mut fixture, mut edge) = stop_and_reopen(|mut scene| async move {
        let entries = session_entries(TWO_BATCH_ENTRIES)?;
        let ids: Vec<_> = entries
            .iter()
            .map(|encoded| federation_object_id(encoded))
            .collect();
        let identity = scene.open_snapshot(&ids).await?;
        for (index, encoded) in entries.iter().enumerate() {
            let entry_index = u32::try_from(index)?;
            let object_id = federation_object_id(encoded);
            scene
                .hub
                .object(encoded, |fragment| FederationFrame::SnapshotEntry {
                    edge_server_id: EDGE,
                    snapshot_token: identity.snapshot_token,
                    entry_index,
                    object_id,
                    fragment,
                })
                .await?;
        }
        scene.gate.arm();
        scene.end_snapshot(identity).await?;
        // The first batch of 256 rows is staged and its receipt is held.
        require_clean(&scene.stop_behind_held_receipt().await?);
        Ok(())
    })
    .await?;
    // The settled batch is durable and unmarked: the next start ignores it.
    let plan = agenc_relay_storage::ReadPlan::range(
        agenc_relay_storage::TableId::EdgeProjection,
        agenc_relay_storage::StoredKey::new(vec![0; 16])?,
        agenc_relay_storage::StoredKey::new(vec![255; 64])?,
        4_096,
    )?;
    let rows = fixture.read_rows(plan)?.records.len();
    assert_eq!(rows, 256, "exactly the first install batch is durable");
    requires_a_fresh_resume(&mut fixture, &mut edge).await
}

#[tokio::test]
async fn a_staged_generation_swap_finishes_before_the_edge_stops() -> TestResult {
    let (_fixture, edge) = stop_and_reopen(|mut scene| async move {
        let identity = scene.reach_ready().await?;
        scene.gate.arm();
        scene
            .hub
            .frame(FederationFrame::SnapshotActive {
                edge_server_id: EDGE,
                identity,
            })
            .await?;
        // The swap is a local durable commit: it must finish, and it does.
        require_clean(&scene.stop_behind_held_receipt().await?);
        Ok(())
    })
    .await?;
    assert_eq!(edge.replica.projection_generation(), SNAPSHOT_GENERATION);
    assert!(!sync::has_durable_ready(&edge));
    assert_eq!(sync::pending_generation(&edge), None);
    Ok(())
}
