#![forbid(unsafe_code)]

//! RUN-08: every durable prefix a kill can leave behind must reconstruct.

use super::*;
use agenc_ircd_storage::{InitialStorageRecord, TableId};

use crate::federation::edge::EdgeRestoreStep;
use crate::state_core::timers::TimerHeap;

/// Connections the load carries. Each one owns two journal identities, one
/// origin and one request, so the set exceeds the journal's own per-batch
/// bound and the drain tears across commits exactly as it does under load.
const CONNECTIONS: u64 = 40;

fn live_edge(context: &mut StateCoreContext) -> TestResult<(EdgeFederation, LinkQueue)> {
    *context.timers_mut() = TimerHeap::new();
    let mut edge = resync_edge();
    let (handle, queue) = link_queue(1 << 20);
    edge.live = Some(LiveLink {
        link: LinkId::new(1),
        handle,
        coordinator_epoch: COORDINATOR_EPOCH,
        coordinator_incarnation: HUB_INCARNATION,
    });
    edge.installed_epoch = Some(COORDINATOR_EPOCH);
    edge.accepted_epoch = Some(COORDINATOR_EPOCH);
    edge.installed_incarnation = Some(HUB_INCARNATION);
    edge.phase = Phase::Active;
    Ok((edge, queue))
}

/// Opens `CONNECTIONS` origins and one session-open request on each.
fn open_load(edge: &mut EdgeFederation, context: &mut StateCoreContext) -> TestResult<()> {
    for index in 0..CONNECTIONS {
        let generation = ConnectionGeneration::new(index.saturating_add(1));
        edge.connection_opened(context, generation);
        edge.origins
            .get_mut(&generation)
            .ok_or("origin")?
            .acked_generation = Some(0);
        request::send_session_open(
            edge,
            context,
            generation,
            1,
            &format!("user{index}"),
            "Load",
            [1; 32],
            None,
        )
        .map_err(|error| format!("session open {index}: {error:?}"))?;
    }
    Ok(())
}

/// Reconstructs a fresh edge from exactly the rows storage holds now.
fn reconstruct_now(fixture: &StateCoreFixture) -> TestResult<()> {
    let mut restored = resync_edge();
    fixture.restore_edge_state(&mut restored, None)?;
    Ok(())
}

/// One session projection record under a seed-derived identity.
fn load_session(seed: u8, nickname: &str) -> TestResult<SessionRecord> {
    session_record(
        SessionId::from_bytes([seed; 16]),
        UserId::from_bytes([seed; 16]),
        nickname,
        1,
        seed,
    )
}

/// Builds the standing projection out of delivered events, so every entry
/// row it names is durable beside the peer row that counts it.
async fn standing_projection(
    edge: &mut EdgeFederation,
    fixture: &mut StateCoreFixture,
    commits: &mut u32,
) -> TestResult<u64> {
    edge.replica.install(1, Vec::new())?;
    let mut sequence = 0_u64;
    for seat in 0..u8::try_from(CONNECTIONS)? {
        let seed = seat.saturating_add(100);
        let record = load_session(seed, &format!("seat{seat}"))?;
        let event = ProjectedEvent::SessionVisible(SessionEventView {
            source: source(record.user_id, &format!("seat{seat}"), seed)?,
            home_projection: Some(record),
        });
        let (descriptor, object) = delivered(&event, sequence, None)?;
        events::receive(edge, fixture.context_mut()?, descriptor, &object)
            .map_err(|error| format!("seat {seat}: {error:?}"))?;
        fixture.commit_staged_batch().await?;
        let _completions = edge.batch_applied(fixture.context_mut()?);
        *commits = commits.saturating_add(1);
        sequence = sequence.saturating_add(1);
    }
    Ok(sequence)
}

/// Builds one delivered projection event at `sequence`.
fn delivered(
    event: &ProjectedEvent,
    sequence: u64,
    correlation: Option<RequestCorrelation>,
) -> TestResult<(agenc_ircd_federation_wire::EventDescriptor, AssembledObject)> {
    let event_id = EventId::from_bytes([u8::try_from(sequence % 200)?.saturating_add(20); 16]);
    let header = EventHeader {
        network_id: NETWORK,
        target_server_id: EDGE,
        projection_generation: 1,
        coordinator_state_generation: sequence.saturating_add(10),
        delivery_sequence: sequence,
        event_id,
        event_kind: event.kind(),
        correlation,
        cross_profile: None,
    };
    let arm = event_arm_object(event).map_err(|error| format!("event arm: {error:?}"))?;
    let bytes = header.build(&arm)?.encode_canonical()?;
    let descriptor = agenc_ircd_federation_wire::EventDescriptor {
        target_server_id: EDGE,
        delivery_sequence: sequence,
        event_id,
        object_id: federation_object_id(bytes.as_slice()),
    };
    let mut assembler = FragmentAssembler::new();
    for fragment in split_fragments(descriptor.object_id, bytes.as_slice())? {
        let frame = FederationFrame::Event {
            descriptor,
            fragment,
        };
        let (_, key) = carrier_of(&frame).map_err(|error| error.to_string())?;
        if let AssemblyProgress::Complete(object) =
            assembler.admit(key, frame.fragment().ok_or("fragment")?, 0)?
        {
            return Ok((descriptor, object));
        }
    }
    Err("event did not assemble".into())
}

#[tokio::test]
async fn an_edge_killed_under_load_reconstructs_every_durable_journal_prefix() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let (mut edge, _queue) = live_edge(fixture.context_mut()?)?;
    open_load(&mut edge, fixture.context_mut()?)?;
    reconstruct_now(&fixture)?;
    let mut commits = 0_u32;
    while journal::has_dirty(&edge) || edge.commit.is_some() {
        if edge.commit.is_none() {
            journal::continue_write(&mut edge, fixture.context_mut()?);
        }
        if edge.commit.is_none() {
            break;
        }
        fixture.commit_staged_batch().await?;
        let _completions = edge.batch_applied(fixture.context_mut()?);
        commits = commits.saturating_add(1);
        reconstruct_now(&fixture).map_err(|error| {
            format!("durable prefix after commit {commits} refused reconstruction: {error}")
        })?;
        if commits > 64 {
            return Err("the journal drain never finished".into());
        }
    }
    assert!(commits > 1, "the load never tore across commits: {commits}");
    Ok(())
}

/// Drains whatever the edge has staged, reconstructing after every commit.
async fn settle(
    edge: &mut EdgeFederation,
    fixture: &mut StateCoreFixture,
    commits: &mut u32,
) -> TestResult<()> {
    let mut guard = 0_u32;
    while journal::has_dirty(edge) || edge.commit.is_some() {
        if edge.commit.is_none() {
            journal::continue_write(edge, fixture.context_mut()?);
        }
        if edge.commit.is_none() {
            break;
        }
        fixture.commit_staged_batch().await?;
        let _completions = edge.batch_applied(fixture.context_mut()?);
        *commits = commits.saturating_add(1);
        reconstruct_now(fixture).map_err(|error| {
            format!("durable prefix after commit {commits} refused reconstruction: {error}")
        })?;
        guard = guard.saturating_add(1);
        if guard > 256 {
            return Err("the drain never finished".into());
        }
    }
    Ok(())
}

#[tokio::test]
async fn an_edge_killed_under_load_reconstructs_every_durable_event_prefix() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let (mut edge, _queue) = live_edge(fixture.context_mut()?)?;
    let mut commits = 0_u32;
    let first = standing_projection(&mut edge, &mut fixture, &mut commits).await?;
    reconstruct_now(&fixture)?;
    open_load(&mut edge, fixture.context_mut()?)?;
    settle(&mut edge, &mut fixture, &mut commits).await?;
    // Deliver the projection changes the load produces, one commit each, and
    // reconstruct from the durable prefix every one of them leaves behind.
    for sequence in first..first.saturating_add(8) {
        let seed = u8::try_from(sequence)?.saturating_add(160);
        let record = load_session(seed, &format!("late{seed}"))?;
        let event = ProjectedEvent::SessionVisible(SessionEventView {
            source: source(record.user_id, &format!("late{seed}"), seed)?,
            home_projection: Some(record),
        });
        let (descriptor, object) = delivered(&event, sequence, None)?;
        events::receive(&mut edge, fixture.context_mut()?, descriptor, &object)
            .map_err(|error| format!("event {sequence}: {error:?}"))?;
        fixture.commit_staged_batch().await?;
        let _completions = edge.batch_applied(fixture.context_mut()?);
        commits = commits.saturating_add(1);
        reconstruct_now(&fixture).map_err(|error| {
            format!("durable prefix after event {sequence} refused reconstruction: {error}")
        })?;
        settle(&mut edge, &mut fixture, &mut commits).await?;
    }
    assert!(commits > 8, "the load never tore across commits: {commits}");
    Ok(())
}

/// A coordinator row that names a pending projection generation, with no
/// marker row for that generation. The restore cannot prove which projection
/// the generation held, so it must refuse, and the refusal must say so.
fn peer_row_naming_a_pending_generation() -> TestResult<Vec<InitialStorageRecord>> {
    use agenc_ircd_storage::federation_records::{
        FederationPeerRecord, PEER_RECORD_KIND, PeerPhase, peer_key,
    };
    let record = FederationPeerRecord {
        fenced_incarnations: Vec::new(),
        server_incarnation: *HUB_INCARNATION.as_bytes(),
        recovery_epoch: *COORDINATOR_EPOCH.as_bytes(),
        accepted_epochs: Vec::new(),
        phase: PeerPhase::Suspended,
        projection_generation: 1,
        next_delivery_sequence: 0,
        cursor: None,
        active_entry_count: 0,
        active_entry_bytes: 0,
        pending_generation: Some(2),
        snapshot_required: true,
        cleanup_cursor: None,
        quarantined: false,
        client_resync_epoch: 0,
    };
    let value = agenc_ircd_storage::PersistentRecordValue::new(
        TableId::FederationPeer,
        PEER_RECORD_KIND,
        1,
        0,
        None,
        Vec::new(),
        record.encode()?,
    )?
    .encode()?;
    Ok(vec![InitialStorageRecord::new(
        TableId::FederationPeer,
        peer_key(COORDINATOR)?,
        1,
        value,
    )?])
}

#[tokio::test]
async fn a_refused_edge_restore_names_the_reconstruction_and_the_record_family() -> TestResult {
    let fixture = StateCoreFixture::with_registration_router_and_records(
        entropy_script(),
        peer_row_naming_a_pending_generation()?,
    )?;
    let mut edge = resync_edge();
    let refusal = fixture
        .restore_edge_refusal(&mut edge, None)?
        .err()
        .ok_or("the restore accepted a pending generation it cannot prove")?;
    assert_eq!(refusal.step, EdgeRestoreStep::ProjectionInstall);
    assert_eq!(
        refusal.error,
        RuntimeError::Storage(agenc_ircd_storage::StorageError::StaleState)
    );
    assert_eq!(
        crate::daemon::DaemonError::from(refusal).to_string(),
        "runtime startup failed: edge federation restore at edge-projection-install refused the \
         recovered state: storage owner failed: storage state is stale or inconsistent",
    );
    Ok(())
}
