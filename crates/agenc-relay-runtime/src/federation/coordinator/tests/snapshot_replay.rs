#![forbid(unsafe_code)]

//! Replay of the durable outbox renders only rows that prove their own key,
//! generation and position, and the snapshot writer and sender stop exactly
//! where the link or the standing projection tells them to.

use super::*;
use crate::bridge::{StorageReadCompletionMessage, StorageReadId};
use crate::state_core::projector::{EdgeDelivery, FederationProjector};
use crate::state_core::timers::{TimedId, TimerKind};
use agenc_relay_federation_wire::DeliveryCursor;
use agenc_relay_storage::federation_records::{OUTBOX_EVENT_KIND, OutboxEventRecord, outbox_key};
use agenc_relay_storage::{ReadRecord, ReadResult, StorageError, StoredKey};
use agenc_relay_types::EventId;

const PEER: ServerId = ServerId::from_bytes([50; 16]);
const STRANGER: ServerId = ServerId::from_bytes([77; 16]);
const INCARNATION: ServerIncarnation = ServerIncarnation::from_bytes([51; 16]);
const RETAINED: EventId = EventId::from_bytes([61; 16]);

struct Replay {
    fixture: StateCoreFixture,
    coordinator: FederationCoordinator,
    queue: LinkQueue,
}

/// Storage holds sequence 0 of generation 0 for the edge; the projector has
/// reserved `reserved` sequences and the edge holds live link 1.
fn replaying(reserved: u64) -> TestResult<Replay> {
    let mut fixture = StateCoreFixture::with_registration_router_and_records(
        entropy_script(),
        vec![resync_outbox_record(PEER)?],
    )?;
    let context = fixture.context_mut()?;
    let mut projector = FederationProjector::new(NETWORK, COORDINATOR);
    projector.set_edge(
        PEER,
        EdgeDelivery {
            projection_generation: 0,
            next_delivery_sequence: reserved,
        },
    );
    context.install_federation_projector(projector);
    let mut coordinator = standalone_coordinator(PEER);
    let (handle, queue) = link_queue(1 << 20);
    coordinator.inbound(context, established(1, PEER, INCARNATION, handle));
    coordinator
        .peers
        .get_mut(&PEER)
        .ok_or("peer")?
        .projection_generation = 0;
    Ok(Replay {
        fixture,
        coordinator,
        queue,
    })
}

impl Replay {
    fn peer(&mut self) -> TestResult<&mut PeerState> {
        Ok(self.coordinator.peers.get_mut(&PEER).ok_or("peer")?)
    }

    /// Starts a replay at `from` and returns the page storage read for it.
    async fn page(&mut self, from: u64) -> TestResult<StorageReadCompletionMessage> {
        let context = self.fixture.context_mut()?;
        snapshot::start_resend(&mut self.coordinator, context, PEER, from);
        let message = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            self.fixture.next_storage_read(),
        )
        .await??;
        if !snapshot::owns_read(&self.coordinator, message.read_id) {
            return Err("the page does not belong to the replay".into());
        }
        Ok(message)
    }

    fn complete(&mut self, message: StorageReadCompletionMessage) -> TestResult {
        let context = self.fixture.context_mut()?;
        snapshot::resend_completed(&mut self.coordinator, context, message);
        Ok(())
    }

    async fn lines(&mut self) -> Vec<String> {
        let mut lines = Vec::new();
        while let Ok(Some(line)) =
            tokio::time::timeout(std::time::Duration::from_millis(20), self.queue.recv()).await
        {
            lines.push(line.as_str().trim_end_matches("\r\n").to_owned());
        }
        lines
    }

    fn retired(&mut self) -> TestResult<bool> {
        Ok(self.peer()?.live.is_none() && self.coordinator.counters.violations == 1)
    }
}

#[tokio::test]
async fn a_retained_row_is_replayed_once_and_the_link_goes_live() -> TestResult {
    let mut replay = replaying(1)?;
    let page = replay.page(0).await?;
    assert!(!snapshot::owns_read(
        &replay.coordinator,
        StorageReadId::new(u64::MAX)
    ));
    replay.complete(page)?;
    let lines = replay.lines().await;
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(
        lines.iter().all(|line| line.contains(" FEVENT ")),
        "{lines:?}"
    );
    assert_eq!(replay.coordinator.counters.events_sent, 1);
    let state = replay.peer()?;
    assert!(state.active && state.resend.is_none());
    assert_eq!(state.outbox.unacked.len(), 1);
    assert!(
        state
            .outbox
            .unacked
            .front()
            .is_some_and(|(sequence, id, _)| *sequence == 0 && *id == RETAINED)
    );
    Ok(())
}

#[tokio::test]
async fn a_page_for_a_read_nobody_issued_changes_nothing() -> TestResult {
    let mut replay = replaying(1)?;
    let page = replay.page(0).await?;
    replay.complete(StorageReadCompletionMessage {
        read_id: StorageReadId::new(u64::MAX),
        result: page.result,
    })?;
    assert!(replay.peer()?.resend.is_some(), "the replay still waits");
    assert_eq!(replay.coordinator.counters.events_sent, 0);
    assert!(replay.lines().await.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_replayed_row_that_contradicts_the_unacknowledged_window_retires_the_link() -> TestResult
{
    let mut replay = replaying(1)?;
    let page = replay.page(0).await?;
    let window = &mut replay.peer()?.outbox;
    window
        .unacked
        .push_back((0, EventId::from_bytes([99; 16]), 5));
    replay.complete(page)?;
    assert!(replay.retired()?);
    assert_eq!(replay.coordinator.counters.events_sent, 0);
    Ok(())
}

#[tokio::test]
async fn a_replay_whose_link_already_ended_is_dropped_without_sending() -> TestResult {
    let mut replay = replaying(1)?;
    let page = replay.page(0).await?;
    replay.peer()?.live = None;
    replay.complete(page)?;
    assert!(replay.peer()?.resend.is_none());
    assert!(!replay.peer()?.active);
    assert_eq!(replay.coordinator.counters.events_sent, 0);
    assert!(replay.lines().await.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_failed_or_undecodable_replay_page_retires_the_link() -> TestResult {
    let mut failed = replaying(1)?;
    let page = failed.page(0).await?;
    failed.complete(StorageReadCompletionMessage {
        read_id: page.read_id,
        result: Err(StorageError::Unavailable),
    })?;
    assert!(failed.retired()?);

    let mut garbled = replaying(1)?;
    let page = garbled.page(0).await?;
    garbled.complete(StorageReadCompletionMessage {
        read_id: page.read_id,
        result: Ok(ReadResult {
            storage_commit_sequence: 1,
            records: vec![ReadRecord {
                table: TableId::EdgeOutbox,
                key: outbox_key(PEER, 0, 0)?,
                sealed_record: vec![0xAB; 64],
            }],
            truncated: false,
        }),
    })?;
    assert!(garbled.retired()?);
    assert_eq!(garbled.coordinator.counters.events_sent, 0);
    Ok(())
}

#[tokio::test]
async fn an_empty_replay_page_below_the_reserved_head_retires_the_link() -> TestResult {
    let mut replay = replaying(2)?;
    let page = replay.page(1).await?;
    assert!(
        page.result
            .as_ref()
            .is_ok_and(|rows| rows.records.is_empty())
    );
    replay.complete(page)?;
    assert!(replay.retired()?);
    Ok(())
}

#[tokio::test]
async fn a_row_of_another_generation_or_position_is_never_replayed() -> TestResult {
    let mut regenerated = replaying(1)?;
    let page = regenerated.page(0).await?;
    regenerated.peer()?.projection_generation = 5;
    regenerated.complete(page)?;
    assert!(regenerated.retired()?);

    // The page of sequence 0 answers a replay that starts at sequence 1.
    let mut displaced = replaying(2)?;
    let first = displaced.page(0).await?;
    let second = displaced.page(1).await?;
    displaced.complete(StorageReadCompletionMessage {
        read_id: second.read_id,
        result: first.result,
    })?;
    assert!(displaced.retired()?);
    assert_eq!(displaced.coordinator.counters.events_sent, 0);
    Ok(())
}

#[tokio::test]
async fn a_second_replay_step_never_issues_a_second_read_for_the_same_page() -> TestResult {
    let mut replay = replaying(1)?;
    let page = replay.page(0).await?;
    let context = replay.fixture.context_mut()?;
    snapshot::continue_resend(&mut replay.coordinator, context, PEER);
    snapshot::continue_resend(&mut replay.coordinator, context, STRANGER);
    assert!(snapshot::owns_read(&replay.coordinator, page.read_id));
    let extra = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        replay.fixture.next_storage_read(),
    )
    .await;
    assert!(extra.is_err(), "no second page was requested");
    Ok(())
}

/// The durable key, record and envelope value of one consistent outbox row.
#[tokio::test]
async fn a_replayed_row_keyed_to_another_edge_retires_the_link() -> TestResult {
    let mut replay = replaying(1)?;
    let mut page = replay.page(0).await?;
    let (record, _) = outbox_row()?;
    let plaintext = PersistentRecordValue::new(
        TableId::EdgeOutbox,
        OUTBOX_EVENT_KIND,
        1,
        0,
        None,
        Vec::new(),
        record.encode()?,
    )?
    .encode()?;
    let key = outbox_key(STRANGER, 0, 0)?;
    let sealed_record = replay
        .fixture
        .seal_row_for_test(TableId::EdgeOutbox, &key, &plaintext)?;
    let result = page
        .result
        .as_mut()
        .map_err(|error| format!("replay page: {error:?}"))?;
    result.records = vec![ReadRecord {
        table: TableId::EdgeOutbox,
        key,
        sealed_record,
    }];
    replay.complete(page)?;
    assert!(replay.retired()?);
    assert_eq!(replay.coordinator.counters.events_sent, 0);
    Ok(())
}

#[tokio::test]
async fn a_replayed_row_whose_size_contradicts_the_window_retires_the_link() -> TestResult {
    let mut replay = replaying(1)?;
    let page = replay.page(0).await?;
    replay.peer()?.outbox.unacked.push_back((0, RETAINED, 1));
    replay.complete(page)?;
    assert!(replay.retired()?);
    assert_eq!(replay.coordinator.counters.events_sent, 0);
    Ok(())
}

fn outbox_row() -> TestResult<(OutboxEventRecord, StoredKey)> {
    let event = ProjectedEvent::NetworkNotice {
        code: "REPLAY".to_owned(),
        text: "committed while disconnected".to_owned(),
    };
    let header = EventHeader {
        network_id: NETWORK,
        target_server_id: PEER,
        projection_generation: 0,
        coordinator_state_generation: 1,
        delivery_sequence: 0,
        event_id: RETAINED,
        event_kind: event.kind(),
        correlation: None,
        cross_profile: None,
    };
    let arm = crate::federation::codec::events::event_arm_object(&event)
        .map_err(|error| format!("{error:?}"))?;
    let bytes = header.build(&arm)?.encode_canonical()?.as_slice().to_vec();
    let record = OutboxEventRecord {
        event_id: *RETAINED.as_bytes(),
        event_object_id: *federation_object_id(&bytes).as_bytes(),
        event_object: bytes,
        coordinator_state_generation: 1,
        acknowledged: false,
        completion_replay_key: None,
    };
    Ok((record, outbox_key(PEER, 0, 0)?))
}

fn decoded(record: &OutboxEventRecord, key: &StoredKey) -> TestResult<Result<(), Violation>> {
    let value = PersistentRecordValue::new(
        TableId::EdgeOutbox,
        agenc_relay_storage::federation_records::OUTBOX_EVENT_KIND,
        1,
        0,
        None,
        Vec::new(),
        record.encode()?,
    )?;
    Ok(snapshot::decode_outbox_record(key, &value).map(|_| ()))
}

#[test]
fn an_outbox_row_stored_under_another_key_is_a_codec_violation() -> TestResult {
    let (record, key) = outbox_row()?;
    assert_eq!(decoded(&record, &key)?, Ok(()));
    for foreign in [
        outbox_key(STRANGER, 0, 0)?,
        outbox_key(PEER, 1, 0)?,
        outbox_key(PEER, 0, 1)?,
    ] {
        assert_eq!(decoded(&record, &foreign)?, Err(Violation::Codec));
    }
    Ok(())
}

#[test]
fn an_outbox_row_whose_envelope_contradicts_its_event_is_a_codec_violation() -> TestResult {
    let (good, key) = outbox_row()?;
    let forgeries = [
        OutboxEventRecord {
            event_id: [9; 16],
            ..good.clone()
        },
        OutboxEventRecord {
            coordinator_state_generation: 2,
            ..good.clone()
        },
        OutboxEventRecord {
            event_object_id: [9; 32],
            ..good.clone()
        },
        OutboxEventRecord {
            completion_replay_key: Some([9; 64]),
            ..good.clone()
        },
        OutboxEventRecord {
            event_object: vec![1, 2, 3],
            ..good
        },
    ];
    for (index, forged) in forgeries.iter().enumerate() {
        assert_eq!(decoded(forged, &key)?, Err(Violation::Codec), "{index}");
    }
    Ok(())
}

struct Cutting {
    fixture: StateCoreFixture,
    coordinator: FederationCoordinator,
    queue: LinkQueue,
}

/// A coordinator whose edge homes one session, linked over `queue_bytes`.
fn cutting(queue_bytes: u64, outbox_bytes: u64) -> TestResult<Cutting> {
    let mut fixture = StateCoreFixture::with_federation_coordinator(
        entropy_script(),
        vec![peer_identity(PEER, "edge.example")],
    )?;
    let context = fixture.context_mut()?;
    let seed = crate::test_support::remote_session_seed(context, PEER, "rae")?;
    let plan = context.domain().plan_session_opened(seed)?;
    crate::test_support::apply_live_plan(context, plan)?;
    let mut coordinator = standalone_coordinator(PEER);
    coordinator.config.outbox_bytes_per_edge = outbox_bytes;
    let (handle, queue) = link_queue(queue_bytes);
    coordinator.inbound(context, established(1, PEER, INCARNATION, handle));
    Ok(Cutting {
        fixture,
        coordinator,
        queue,
    })
}

impl Cutting {
    fn open(&mut self) -> TestResult<Result<(), Violation>> {
        let context = self.fixture.context_mut()?;
        Ok(snapshot::resume(
            &mut self.coordinator,
            context,
            LinkId::new(1),
            PEER,
            9,
            DeliveryCursor::Empty,
        ))
    }

    fn progress(&mut self) -> TestResult<(usize, usize, bool)> {
        let snapshot = self
            .coordinator
            .peers
            .get(&PEER)
            .and_then(|state| state.snapshot.as_ref())
            .ok_or("no snapshot")?;
        Ok((
            snapshot.next_send,
            snapshot.entries.len(),
            snapshot.end_sent,
        ))
    }

    async fn drain(&mut self) -> usize {
        let mut lines = 0;
        while let Ok(Some(_line)) =
            tokio::time::timeout(std::time::Duration::from_millis(20), self.queue.recv()).await
        {
            lines += 1;
        }
        lines
    }
}

#[tokio::test]
async fn snapshot_entries_wait_while_the_link_queue_is_above_its_watermark() -> TestResult {
    let mut cutting = cutting(1 << 20, 0)?;
    assert_eq!(cutting.open()?, Ok(()));
    let (sent, entries, end_sent) = cutting.progress()?;
    assert!(entries > 0, "the homed session stands in the cut");
    assert_eq!((sent, end_sent), (0, false), "BEGIN still fills the queue");
    let context = cutting.fixture.context_mut()?;
    let deadline = context.now().checked_add(20)?;
    let paced = context
        .timers_mut()
        .pop_due(deadline)
        .ok_or("no pacing timer")?;
    assert_eq!(paced.kind, TimerKind::FederationSnapshotSend);
    assert_eq!(paced.id, TimedId::Peer(PEER));

    assert_eq!(cutting.drain().await, 2, "RESUME SNAPSHOT and BEGIN");
    let context = cutting.fixture.context_mut()?;
    assert!(snapshot::timer_fired(
        &mut cutting.coordinator,
        context,
        paced
    ));
    let (sent, _entries, _end_sent) = cutting.progress()?;
    assert_eq!(
        sent, 1,
        "one entry fits before the queue is above zero again"
    );
    Ok(())
}

#[tokio::test]
async fn a_finished_or_foreign_snapshot_send_step_queues_nothing() -> TestResult {
    let mut cutting = cutting(1 << 20, 1 << 20)?;
    assert_eq!(cutting.open()?, Ok(()));
    let (sent, entries, end_sent) = cutting.progress()?;
    assert_eq!((sent, end_sent), (entries, true));
    let queued = cutting.drain().await;
    assert!(queued > 2);
    let context = cutting.fixture.context_mut()?;
    snapshot::continue_send(&mut cutting.coordinator, context, PEER);
    snapshot::continue_send(&mut cutting.coordinator, context, STRANGER);
    assert_eq!(cutting.drain().await, 0, "END is sent once");

    // A snapshot opened for an older link is never sent over a newer one.
    let (handle, mut newer) = link_queue(1 << 20);
    if let Some(snapshot) = cutting
        .coordinator
        .peers
        .get_mut(&PEER)
        .and_then(|state| state.snapshot.as_mut())
    {
        snapshot.end_sent = false;
        snapshot.next_send = 0;
    }
    let context = cutting.fixture.context_mut()?;
    cutting
        .coordinator
        .inbound(context, established(2, PEER, INCARNATION, handle));
    snapshot::continue_send(&mut cutting.coordinator, context, PEER);
    let idle = tokio::time::timeout(std::time::Duration::from_millis(50), newer.recv()).await;
    assert!(
        idle.is_err(),
        "the newer link received a stale snapshot line"
    );
    Ok(())
}

#[test]
fn cut_rows_a_later_mutation_replaced_are_skipped_not_written() -> TestResult {
    let mut cutting = cutting(1 << 20, 1 << 20)?;
    assert_eq!(cutting.open()?, Ok(()));
    let entries = cutting.progress()?.1;
    // The marker batch is refused, so the writer is free to run.
    cutting
        .fixture
        .state_mut()?
        .reject_fixture_batch_before_submission(StorageError::QueueFull)?;
    let context = cutting.fixture.context_mut()?;
    snapshot::continue_write(&mut cutting.coordinator, context, PEER);
    assert!(
        matches!(
            cutting.coordinator.pending,
            Some(PendingCommit::SnapshotRows { peer: PEER })
        ),
        "a commit is already pending, so no page is staged over it"
    );
    cutting.coordinator.pending = None;
    // Every standing key of the edge was removed after the cut.
    context
        .federation_mut()
        .ok_or("projector")?
        .install_edge(PEER, &[]);
    let step = snapshot::write_batch(&mut cutting.coordinator, context, PEER);
    assert!(matches!(step, snapshot::WriteStep::Skipped));
    assert!(cutting.coordinator.pending.is_none());
    assert_eq!(context.pending_len(), 0);
    let written = cutting
        .coordinator
        .peers
        .get(&PEER)
        .and_then(|state| state.snapshot.as_ref())
        .map(|snapshot| snapshot.next_write);
    assert_eq!(written, Some(entries));
    snapshot::continue_write(&mut cutting.coordinator, context, PEER);
    assert!(cutting.coordinator.pending.is_none(), "nothing is left");
    Ok(())
}

#[test]
fn a_barrier_resume_answers_only_a_live_link_of_a_loaded_coordinator() -> TestResult {
    let mut cutting = cutting(1 << 20, 1 << 20)?;
    let context = cutting.fixture.context_mut()?;
    if let Some(state) = cutting.coordinator.peers.get_mut(&PEER) {
        state.outbox.cursor = Some((4, RETAINED));
    }
    snapshot::barrier_resume_committed(&mut cutting.coordinator, context, PEER, LinkId::new(9));
    snapshot::barrier_resume_committed(&mut cutting.coordinator, context, PEER, LinkId::new(1));
    assert!(!cutting.coordinator.loaded());
    let state = cutting.coordinator.peers.get(&PEER).ok_or("peer")?;
    assert!(state.resend.is_none() && !state.active);
    Ok(())
}
