#![forbid(unsafe_code)]

//! FRESUME, the base snapshot and its READY refuse every frame that arrives
//! outside their one permitted phase, and a generation nobody can finish is
//! dropped with its link.

use super::*;
use crate::state_core::timers::{TimedId, TimerEntry, TimerKind};
use agenc_relay_federation_wire::{DeliveryCursor, SnapshotIdentity};

const PEER: ServerId = ServerId::from_bytes([50; 16]);
const STRANGER: ServerId = ServerId::from_bytes([77; 16]);
const INCARNATION: ServerIncarnation = ServerIncarnation::from_bytes([51; 16]);

struct Bench {
    fixture: StateCoreFixture,
    coordinator: FederationCoordinator,
    queue: LinkQueue,
}

/// A coordinator whose one edge holds live link 1.
fn linked() -> TestResult<Bench> {
    linked_with(1 << 20)
}

fn linked_with(queue_bytes: u64) -> TestResult<Bench> {
    let mut fixture = StateCoreFixture::with_federation_coordinator(
        entropy_script(),
        vec![peer_identity(PEER, "edge.example")],
    )?;
    let mut coordinator = standalone_coordinator(PEER);
    let (handle, queue) = link_queue(queue_bytes);
    coordinator.inbound(
        fixture.context_mut()?,
        established(1, PEER, INCARNATION, handle),
    );
    Ok(Bench {
        fixture,
        coordinator,
        queue,
    })
}

impl Bench {
    fn resume(&mut self, generation: u64, cursor: DeliveryCursor) -> Result<(), Violation> {
        let context = self.fixture.context_mut().map_err(|_| Violation::Codec)?;
        snapshot::resume(
            &mut self.coordinator,
            context,
            LinkId::new(1),
            PEER,
            generation,
            cursor,
        )
    }

    fn ready(&mut self, identity: SnapshotIdentity) -> Result<(), Violation> {
        let context = self.fixture.context_mut().map_err(|_| Violation::Codec)?;
        snapshot::ready(
            &mut self.coordinator,
            context,
            LinkId::new(1),
            PEER,
            identity,
        )
    }

    fn peer(&mut self) -> TestResult<&mut PeerState> {
        Ok(self.coordinator.peers.get_mut(&PEER).ok_or("peer")?)
    }

    /// Opens generation 1 by a resume that names nothing retained.
    fn open_snapshot(&mut self) -> TestResult<SnapshotIdentity> {
        self.resume(9, DeliveryCursor::Empty)
            .map_err(|violation| format!("{violation:?}"))?;
        let identity = self
            .peer()?
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.identity)
            .ok_or("no snapshot opened")?;
        Ok(identity)
    }

    /// Every line queued for the edge so far.
    async fn lines(&mut self) -> Vec<String> {
        let mut lines = Vec::new();
        while let Ok(Some(line)) =
            tokio::time::timeout(std::time::Duration::from_millis(20), self.queue.recv()).await
        {
            lines.push(line.as_str().trim_end_matches("\r\n").to_owned());
        }
        lines
    }
}

fn parsed(lines: &[String]) -> TestResult<Vec<FederationFrame>> {
    lines
        .iter()
        .map(|text| {
            parse_frame(text, COORDINATOR_NAME).map_err(|error| format!("{error:?}: {text}").into())
        })
        .collect()
}

/// A due timer entry of `kind` for `id`, as the timer heap would deliver it.
fn due_timer(bench: &mut Bench, kind: TimerKind, id: TimedId) -> TestResult<TimerEntry> {
    let context = bench.fixture.context_mut()?;
    let now = context.now();
    let _cancelled = context.timers_mut().cancel(kind, id);
    context.timers_mut().schedule(now, kind, id)?;
    while let Some(entry) = context.timers_mut().pop_due(now) {
        if entry.kind == kind && entry.id == id {
            return Ok(entry);
        }
    }
    Err("the scheduled timer never came due".into())
}

fn fire(bench: &mut Bench, kind: TimerKind, id: TimedId) -> TestResult<bool> {
    let entry = due_timer(bench, kind, id)?;
    let context = bench.fixture.context_mut()?;
    Ok(snapshot::timer_fired(
        &mut bench.coordinator,
        context,
        entry,
    ))
}

#[test]
fn a_resume_is_refused_while_a_commit_is_pending_or_for_a_stranger() -> TestResult {
    let mut bench = linked()?;
    bench.coordinator.pending = Some(PendingCommit::SnapshotRows { peer: PEER });
    assert_eq!(
        bench.resume(0, DeliveryCursor::Empty),
        Err(Violation::Ceiling)
    );
    bench.coordinator.pending = None;
    let context = bench.fixture.context_mut()?;
    assert_eq!(
        snapshot::resume(
            &mut bench.coordinator,
            context,
            LinkId::new(1),
            STRANGER,
            0,
            DeliveryCursor::Empty
        ),
        Err(Violation::Misaddressed)
    );
    Ok(())
}

#[test]
fn a_resume_on_an_active_or_replaying_link_is_a_phase_violation() -> TestResult {
    let mut bench = linked()?;
    bench.peer()?.active = true;
    assert_eq!(
        bench.resume(1, DeliveryCursor::Empty),
        Err(Violation::Phase)
    );
    bench.peer()?.active = false;

    // A replay with a page outstanding keeps the link in its resume phase.
    let context = bench.fixture.context_mut()?;
    context.federation_mut().ok_or("projector")?.set_edge(
        PEER,
        crate::state_core::projector::EdgeDelivery {
            projection_generation: 1,
            next_delivery_sequence: 3,
        },
    );
    snapshot::start_resend(&mut bench.coordinator, context, PEER, 0);
    assert!(bench.peer()?.resend.is_some());
    assert_eq!(
        bench.resume(1, DeliveryCursor::Empty),
        Err(Violation::Phase)
    );
    Ok(())
}

#[tokio::test]
async fn a_retained_empty_cursor_resumes_without_a_snapshot() -> TestResult {
    let mut bench = linked()?;
    assert_eq!(bench.resume(1, DeliveryCursor::Empty), Ok(()));
    let lines = bench.lines().await;
    assert!(
        matches!(
            parsed(&lines)?.as_slice(),
            [FederationFrame::ResumeOk {
                projection_generation: 1,
                next_delivery_sequence: 0,
                ..
            }]
        ),
        "{lines:?}"
    );
    let state = bench.peer()?;
    assert!(state.active, "nothing was reserved, so the link is live");
    assert!(state.snapshot.is_none());
    Ok(())
}

#[tokio::test]
async fn a_cursor_the_coordinator_never_retained_opens_the_next_generation() -> TestResult {
    let mut bench = linked()?;
    let cursor = DeliveryCursor::At {
        delivery_sequence: 4,
        event_id: agenc_relay_types::EventId::from_bytes([61; 16]),
    };
    assert_eq!(bench.resume(1, cursor), Ok(()));
    let lines = bench.lines().await;
    assert!(
        matches!(
            parsed(&lines)?.as_slice(),
            [
                FederationFrame::ResumeSnapshot { .. },
                FederationFrame::SnapshotBegin { entry_count: 0, .. },
                FederationFrame::SnapshotEnd { .. }
            ]
        ),
        "{lines:?}"
    );
    assert_eq!(bench.peer()?.projection_generation, 2);
    assert!(matches!(
        bench.coordinator.pending,
        Some(PendingCommit::SnapshotRows { peer: PEER })
    ));
    Ok(())
}

#[test]
fn a_resume_during_an_unfinished_snapshot_opens_a_fresh_generation() -> TestResult {
    let mut bench = linked()?;
    let first = bench.open_snapshot()?;
    assert_eq!(first.projection_generation, 10, "counts on from the edge");
    bench.coordinator.pending = None;
    bench
        .fixture
        .state_mut()?
        .reject_fixture_batch_before_submission(agenc_relay_storage::StorageError::QueueFull)?;
    assert_eq!(bench.resume(10, DeliveryCursor::Empty), Ok(()));
    let second = bench
        .peer()?
        .snapshot
        .as_ref()
        .map(|snapshot| snapshot.identity)
        .ok_or("snapshot")?;
    assert_eq!(second.projection_generation, 11);
    assert_ne!(second.snapshot_token, first.snapshot_token);
    Ok(())
}

#[test]
fn ready_is_refused_outside_the_one_snapshot_it_answers() -> TestResult {
    let mut bench = linked()?;
    let stranger_identity = SnapshotIdentity {
        snapshot_token: FederationHash32::from_bytes([1; 32]),
        recovery_epoch: RecoveryEpoch::from_bytes([34; 16]),
        projection_generation: 1,
        state_generation: 0,
        snapshot_digest: FederationHash32::from_bytes([2; 32]),
    };
    assert_eq!(bench.ready(stranger_identity), Err(Violation::Phase));
    let identity = bench.open_snapshot()?;
    assert_eq!(
        bench.ready(identity),
        Err(Violation::Ceiling),
        "the marker row is still pending"
    );
    bench.coordinator.pending = None;
    assert_eq!(bench.ready(stranger_identity), Err(Violation::Origin));
    if let Some(snapshot) = bench.peer()?.snapshot.as_mut() {
        snapshot.end_sent = false;
    }
    assert_eq!(bench.ready(identity), Err(Violation::Origin));
    if let Some(snapshot) = bench.peer()?.snapshot.as_mut() {
        snapshot.end_sent = true;
        snapshot.ready = true;
    }
    assert_eq!(
        bench.ready(identity),
        Err(Violation::Origin),
        "READY is accepted once"
    );
    Ok(())
}

#[tokio::test]
async fn a_repeated_ready_gets_the_identical_active_line() -> TestResult {
    let mut bench = linked()?;
    let identity = bench.open_snapshot()?;
    let _opening = bench.lines().await;
    bench.coordinator.pending = None;
    let context = bench.fixture.context_mut()?;
    snapshot::ready_committed(&mut bench.coordinator, context, PEER);
    snapshot::ready_committed(&mut bench.coordinator, context, PEER);
    snapshot::ready_committed(&mut bench.coordinator, context, STRANGER);
    assert_eq!(bench.peer()?.ready_identity, Some(identity));
    bench.peer()?.active = false;
    assert_eq!(bench.ready(identity), Ok(()));
    let lines = bench.lines().await;
    let [first, second] = lines.as_slice() else {
        return Err(format!("expected two ACTIVE lines: {lines:?}").into());
    };
    assert_eq!(first, second, "the repeated ACTIVE is byte-identical");
    assert!(matches!(
        parsed(&lines)?.as_slice(),
        [FederationFrame::SnapshotActive { identity: sent, .. }, _] if *sent == identity
    ));
    assert!(bench.peer()?.active);
    Ok(())
}

#[test]
fn a_rejected_snapshot_drops_its_generation_and_retires_only_its_own_link() -> TestResult {
    let mut bench = linked()?;
    let _identity = bench.open_snapshot()?;
    let context = bench.fixture.context_mut()?;
    snapshot::rejected(&mut bench.coordinator, context, STRANGER);
    snapshot::rejected(&mut bench.coordinator, context, PEER);
    assert!(bench.peer()?.snapshot.is_none());
    assert!(
        bench.peer()?.live.is_none(),
        "the snapshot's link is retired"
    );
    assert_eq!(bench.coordinator.counters.violations, 1);
    // Nothing is left to reject, and a newer link is never retired for it.
    let context = bench.fixture.context_mut()?;
    snapshot::rejected(&mut bench.coordinator, context, PEER);
    assert_eq!(bench.coordinator.counters.violations, 1);
    Ok(())
}

#[test]
fn a_rejected_snapshot_of_an_older_link_leaves_the_newer_link_alone() -> TestResult {
    let mut bench = linked()?;
    let _identity = bench.open_snapshot()?;
    let (handle, _newer_queue) = link_queue(1 << 20);
    let context = bench.fixture.context_mut()?;
    bench
        .coordinator
        .inbound(context, established(2, PEER, INCARNATION, handle));
    let kept = bench.peer()?.snapshot.is_some();
    let context = bench.fixture.context_mut()?;
    snapshot::rejected(&mut bench.coordinator, context, PEER);
    assert!(
        bench
            .peer()?
            .live
            .as_ref()
            .is_some_and(|live| live.link == LinkId::new(2)),
        "kept={kept}"
    );
    assert_eq!(bench.coordinator.counters.violations, 0);
    Ok(())
}

#[test]
fn snapshot_timers_belong_to_federation_only_for_a_peer_and_its_kinds() -> TestResult {
    let mut bench = linked()?;
    let connection = TimedId::Connection(crate::connection::ConnectionGeneration::new(1));
    assert!(!fire(
        &mut bench,
        TimerKind::FederationSnapshotExpiry,
        connection
    )?);
    assert!(!fire(
        &mut bench,
        TimerKind::FederationResumeRetry,
        TimedId::Peer(PEER)
    )?);
    for kind in [
        TimerKind::FederationSnapshotSend,
        TimerKind::FederationSnapshotExpiry,
    ] {
        for peer in [PEER, STRANGER] {
            assert!(fire(&mut bench, kind, TimedId::Peer(peer))?);
        }
    }
    assert!(bench.peer()?.live.is_some(), "no snapshot, nothing expired");
    Ok(())
}

#[test]
fn an_expired_snapshot_is_dropped_with_its_link_unless_ready_arrived() -> TestResult {
    let mut bench = linked()?;
    let _identity = bench.open_snapshot()?;
    if let Some(snapshot) = bench.peer()?.snapshot.as_mut() {
        snapshot.ready = true;
    }
    let expiry = TimerKind::FederationSnapshotExpiry;
    assert!(fire(&mut bench, expiry, TimedId::Peer(PEER))?);
    assert!(bench.peer()?.snapshot.is_some(), "READY is being recorded");
    if let Some(snapshot) = bench.peer()?.snapshot.as_mut() {
        snapshot.ready = false;
    }
    assert!(fire(&mut bench, expiry, TimedId::Peer(PEER))?);
    assert!(bench.peer()?.snapshot.is_none());
    assert!(bench.peer()?.live.is_none());
    assert_eq!(bench.coordinator.counters.violations, 1);
    Ok(())
}

#[test]
fn an_expired_snapshot_of_an_older_link_keeps_the_newer_link() -> TestResult {
    let mut bench = linked()?;
    let _identity = bench.open_snapshot()?;
    let (handle, _newer_queue) = link_queue(1 << 20);
    let context = bench.fixture.context_mut()?;
    bench
        .coordinator
        .inbound(context, established(2, PEER, INCARNATION, handle));
    assert!(
        bench.peer()?.snapshot.is_some(),
        "a reconnect alone does not drop the generation"
    );
    assert!(fire(
        &mut bench,
        TimerKind::FederationSnapshotExpiry,
        TimedId::Peer(PEER)
    )?);
    assert!(bench.peer()?.snapshot.is_none());
    assert!(bench.peer()?.live.is_some());
    assert_eq!(bench.coordinator.counters.violations, 0);
    Ok(())
}
