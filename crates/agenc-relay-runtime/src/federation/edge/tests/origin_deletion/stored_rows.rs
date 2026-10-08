#![forbid(unsafe_code)]

//! A deleted origin's journal row names the generation and next sequence
//! its deletion named (spec 20.7): the update a link carried ahead of the
//! deletion at sequence zero, or else the acknowledged declaration with its
//! next operation sequence, never an update no link carried. An edge that
//! restarts before the deletion's acknowledgement is durable therefore
//! replays the deletion its live link sent, which the coordinator, ready
//! again with the origin already deleted, accepts.

use agenc_relay_federation_wire::{FederationHash32, OriginRecord};
use agenc_relay_storage::federation_records::{
    FederationOriginRecord, ORIGIN_FLAG_PENDING_DEL, ORIGIN_FLAG_SINK_GONE, ORIGIN_RECORD_KIND,
    OriginRowStatus, origin_key,
};
use agenc_relay_storage::{
    InitialStorageRecord, PersistentRecordValue, ReadPlan, StoredKey, TableId,
};
use agenc_relay_types::OriginId;

use super::*;

/// The generation and next sequence of every deletion among `frames`.
fn deletions(frames: &[FederationFrame]) -> Vec<(u64, u64)> {
    frames
        .iter()
        .filter_map(|frame| match frame {
            FederationFrame::OriginDel {
                generation,
                next_operation_sequence,
                ..
            } => Some((*generation, *next_operation_sequence)),
            _ => None,
        })
        .collect()
}

/// The generations at which this edge's storage holds a row of `origin`.
fn stored_generations(fixture: &StateCoreFixture, origin: OriginId) -> TestResult<Vec<u64>> {
    let plan = ReadPlan::range(
        TableId::FederationOrigin,
        StoredKey::new(vec![0; 56])?,
        StoredKey::new(vec![255; 64])?,
        4_096,
    )?;
    let keys: Vec<StoredKey> = fixture
        .read_rows(plan)?
        .records
        .into_iter()
        .map(|record| record.key)
        .collect();
    let mut generations = Vec::new();
    for generation in 0..4 {
        let key = origin_key(EDGE, EDGE_INCARNATION, *origin.as_bytes(), generation)?;
        if keys.contains(&key) {
            generations.push(generation);
        }
    }
    Ok(generations)
}

/// The origin the restored edge holds for `origin_id`.
fn restored(
    edge: &EdgeFederation,
    origin_id: OriginId,
) -> TestResult<(ConnectionGeneration, &ConnectionOrigin)> {
    edge.origins
        .iter()
        .find(|(_, origin)| origin.origin_id == origin_id)
        .map(|(connection, origin)| (*connection, origin))
        .ok_or_else(|| "the restart restored no such origin".into())
}

/// Reopens the fixture's storage as a restarted process does, restores a
/// fresh edge from it and relinks that edge, which replays its origins.
/// The restored origin's row is `stored`, exactly. Returns the restarted
/// edge, the restored origin's connection and the deletions it replayed.
async fn restart_and_relink(
    fixture: &mut StateCoreFixture,
    origin_id: OriginId,
    stored: &FederationOriginRecord,
) -> TestResult<(EdgeFederation, ConnectionGeneration, Vec<(u64, u64)>)> {
    fixture.restart_registration_storage(entropy_script())?;
    let mut restarted = resync_edge();
    fixture.restore_edge_state(&mut restarted, None)?;
    let (connection, origin) = restored(&restarted, origin_id)?;
    assert!(origin.deleted && !origin.del_acked);
    assert_eq!(
        &row(&restarted, connection)?,
        stored,
        "the restored origin rewrites its row unchanged"
    );
    let mut relinked = resync_snapshot_link(&mut restarted);
    restarted.phase = Phase::Origins;
    request::replay_origin(&mut restarted, fixture.context_mut()?, connection);
    let replayed = deletions(&origin_frames(&mut relinked).await?);
    Ok((restarted, connection, replayed))
}

fn row(
    edge: &EdgeFederation,
    connection: ConnectionGeneration,
) -> TestResult<FederationOriginRecord> {
    journal::origin_record(edge, connection).map_err(|violation| format!("{violation:?}").into())
}

fn object_id(record: &OriginRecord) -> TestResult<[u8; 32]> {
    Ok(*federation_object_id(record.to_object()?.encode_canonical()?.as_slice()).as_bytes())
}

#[tokio::test]
async fn a_deletion_whose_update_no_link_carried_is_stored_at_the_acknowledged_generation()
-> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let connection = ConnectionGeneration::new(1);
    let (mut edge, mut queue) = bound(&mut fixture, connection).await?;
    let _declared = origin_frames(&mut queue).await?;
    let origin = edge.origins.get(&connection).ok_or("origin")?;
    let (origin_id, acknowledged) = (origin.origin_id, origin.object_id);
    assert!(edge.commit.is_some(), "the update's row is being written");
    edge.connection_closed(fixture.context_mut()?, connection, "");
    commit_edge_batches(&mut edge, &mut fixture).await?;
    let sent = deletions(&origin_frames(&mut queue).await?);
    assert_eq!(sent, [(0, EXECUTED)], "the live deletion");
    let stored = row(&edge, connection)?;
    assert_eq!(stored.origin_object_id, acknowledged);
    assert_eq!(stored.next_sequence, EXECUTED);
    assert_eq!(stored.status, OriginRowStatus::Deleted);
    assert_eq!(
        stored.flags,
        ORIGIN_FLAG_SINK_GONE | ORIGIN_FLAG_PENDING_DEL
    );
    assert_eq!(
        stored_generations(&fixture, origin_id)?,
        [0],
        "the update's row went with the batch that wrote the deletion's"
    );
    let (restarted, restored_connection, replayed) =
        restart_and_relink(&mut fixture, origin_id, &stored).await?;
    let origin = restarted
        .origins
        .get(&restored_connection)
        .ok_or("origin")?;
    assert_eq!(
        (origin.generation, origin.sequence, origin.object_id),
        (0, EXECUTED, acknowledged)
    );
    assert_eq!(
        replayed, sent,
        "the restarted edge replays the same deletion"
    );
    Ok(())
}

#[tokio::test]
async fn a_deletion_naming_the_carried_update_is_stored_at_its_generation() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let connection = ConnectionGeneration::new(1);
    let (mut edge, mut queue) = bound(&mut fixture, connection).await?;
    let origin = edge.origins.get(&connection).ok_or("origin")?;
    let origin_id = origin.origin_id;
    let update = origin.pending_updates.front().copied().ok_or("update")?;
    commit_edge_batches(&mut edge, &mut fixture).await?;
    assert!(updates(&origin_frames(&mut queue).await?) > 0, "carried");
    edge.connection_closed(fixture.context_mut()?, connection, "");
    commit_edge_batches(&mut edge, &mut fixture).await?;
    let sent = deletions(&origin_frames(&mut queue).await?);
    assert_eq!(sent, [(1, 0)], "the live deletion");
    let stored = row(&edge, connection)?;
    assert_eq!(stored.origin_object_id, object_id(&update)?);
    assert_eq!(stored.next_sequence, 0);
    assert_eq!(stored.status, OriginRowStatus::Deleted);
    assert_eq!(stored_generations(&fixture, origin_id)?, [0, 1]);
    let (restarted, restored_connection, replayed) =
        restart_and_relink(&mut fixture, origin_id, &stored).await?;
    let origin = restarted
        .origins
        .get(&restored_connection)
        .ok_or("origin")?;
    assert_eq!((origin.generation, origin.sequence), (1, 0));
    assert_eq!(
        replayed, sent,
        "the restarted edge replays the same deletion"
    );
    Ok(())
}

/// Once the first update is acknowledged, the held generation names its
/// principal: a second update no link carried leaves the row at the first
/// update's generation, with the object the coordinator acknowledged.
#[tokio::test]
async fn a_deletion_after_an_acknowledged_update_is_stored_at_that_generation() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let connection = ConnectionGeneration::new(1);
    let (mut edge, mut queue) = bound(&mut fixture, connection).await?;
    commit_edge_batches(&mut edge, &mut fixture).await?;
    let origin = edge.origins.get(&connection).ok_or("origin")?;
    let origin_id = origin.origin_id;
    let update = origin.pending_updates.front().copied().ok_or("update")?;
    let _carried = origin_frames(&mut queue).await?;
    let acknowledged = object_id(&update)?;
    edge.handle_frame(
        fixture.context_mut()?,
        FederationFrame::OriginAck {
            edge_server_id: EDGE,
            server_incarnation: EDGE_INCARNATION,
            origin_id,
            generation: 1,
            object_id: Some(FederationHash32::from_bytes(acknowledged)),
        },
    )
    .map_err(|violation| format!("the acknowledgement was refused: {violation:?}"))?;
    let origin = edge.origins.get_mut(&connection).ok_or("origin")?;
    origin.account = Some((agenc_relay_testkit::account_id(5), 1));
    edge.session_bound(fixture.context_mut()?, connection);
    edge.connection_closed(fixture.context_mut()?, connection, "");
    commit_edge_batches(&mut edge, &mut fixture).await?;
    let sent = deletions(&origin_frames(&mut queue).await?);
    assert_eq!(sent, [(1, 0)], "the live deletion");
    let stored = row(&edge, connection)?;
    assert_eq!(stored.origin_object_id, acknowledged);
    assert_eq!(
        stored_generations(&fixture, origin_id)?,
        [0, 1],
        "the second update's row went with the batch that wrote the deletion's"
    );
    let (restarted, restored_connection, replayed) =
        restart_and_relink(&mut fixture, origin_id, &stored).await?;
    let origin = restarted
        .origins
        .get(&restored_connection)
        .ok_or("origin")?;
    assert_eq!(
        (origin.generation, origin.sequence, origin.object_id),
        (1, 0, acknowledged)
    );
    assert_eq!(
        replayed, sent,
        "the restarted edge replays the same deletion"
    );
    Ok(())
}

/// An origin deleted while an update it never sent is pending: the first
/// link's deletion names the acknowledged generation and the coordinator
/// commits it. The edge restarts before the deletion's acknowledgement is
/// durable and restores the origin from its journal row; the coordinator,
/// ready again with the origin already deleted, takes the restarted edge's
/// deletion, which names what the first one did.
#[tokio::test]
async fn a_restarted_deletion_names_what_the_first_one_did() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let connection = ConnectionGeneration::new(1);
    let (mut edge, mut queue) = bound(&mut fixture, connection).await?;
    let _declared = origin_frames(&mut queue).await?;
    let origin = edge.origins.get(&connection).ok_or("origin")?;
    let update = origin.pending_updates.front().copied().ok_or("update")?;
    let (mut table, key) = coordinator_table(origin)?;
    edge.connection_closed(fixture.context_mut()?, connection, "");
    commit_edge_batches(&mut edge, &mut fixture).await?;
    let frames = origin_frames(&mut queue).await?;
    let origin = edge.origins.get(&connection).ok_or("origin")?;
    assert_eq!(
        replay(&mut table, key, origin, &update, &frames)?,
        Some((0, EXECUTED)),
        "the first deletion names the acknowledged generation"
    );
    // The row the journal holds for the deleted origin, under the key of
    // the generation it names.
    let stored = row(&edge, connection)?;
    let mut budget = agenc_relay_federation_wire::DecodeBudget::new(4_096, 64);
    let named = agenc_relay_federation_wire::SchemaObject::decode_exact(
        "FederationOrigin",
        &stored.origin_object,
        &mut budget,
    )
    .and_then(|object| OriginRecord::from_object(&object))?;
    let record = InitialStorageRecord::new(
        TableId::FederationOrigin,
        origin_key(
            EDGE,
            EDGE_INCARNATION,
            *origin.origin_id.as_bytes(),
            named.generation,
        )?,
        1,
        PersistentRecordValue::new(
            TableId::FederationOrigin,
            ORIGIN_RECORD_KIND,
            1,
            0,
            None,
            Vec::new(),
            stored.encode()?,
        )?
        .encode()?,
    )?;
    let origin_id = origin.origin_id;
    let mut restart =
        StateCoreFixture::with_registration_router_and_records(entropy_script(), vec![record])?;
    let mut restarted = resync_edge();
    restart.restore_edge_state(&mut restarted, None)?;
    let (restored_connection, _) = restored(&restarted, origin_id)?;
    // The coordinator: the link is lost, the edge's RESET arrives, and READY
    // follows at once since the edge's only origin is already deleted.
    table.link_lost(
        EDGE,
        EDGE_INCARNATION,
        agenc_relay_types::MonotonicTick::from_ticks(1),
    )?;
    table.reset(EDGE, EDGE_INCARNATION);
    table.ready(EDGE, EDGE_INCARNATION)?;
    let mut relinked = resync_snapshot_link(&mut restarted);
    restarted.phase = Phase::Origins;
    request::replay_origin(&mut restarted, restart.context_mut()?, restored_connection);
    let frames = origin_frames(&mut relinked).await?;
    let restored = restarted
        .origins
        .get(&restored_connection)
        .ok_or("origin")?;
    assert_eq!(
        replay(&mut table, key, restored, &update, &frames)?,
        Some((0, EXECUTED)),
        "the restarted edge's deletion names what the first one did"
    );
    Ok(())
}
