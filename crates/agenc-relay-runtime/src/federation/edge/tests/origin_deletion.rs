#![forbid(unsafe_code)]

//! An origin deletion names the generation the coordinator holds (spec
//! 20.7): the generation of the last declaration this link carried, which
//! precedes the DEL on the link, or else the acknowledged generation with
//! its next operation sequence. The frames the edge sends are replayed into
//! the coordinator's origin table, which accepts a DEL only at the exact
//! generation it holds while the link is up.

use agenc_relay_domain::federation::{
    OperationKey, OriginBinding, OriginDeclaration, OriginKey, OriginPrincipal, OriginTable,
};
use agenc_relay_types::RequestId;

use super::*;

mod stored_rows;

/// The requests the coordinator executed under generation zero.
const EXECUTED: u64 = 3;

/// An active edge on a live link whose one connection's generation-zero
/// declaration was sent and acknowledged after `EXECUTED` requests ran
/// under it, and whose session is now bound, queueing the update.
async fn bound(
    fixture: &mut StateCoreFixture,
    connection: ConnectionGeneration,
) -> TestResult<(EdgeFederation, LinkQueue)> {
    let mut edge = resync_edge();
    let queue = resync_snapshot_link(&mut edge);
    edge.phase = Phase::Active;
    edge.connection_opened(fixture.context_mut()?, connection);
    commit_edge_batches(&mut edge, fixture).await?;
    let origin = edge.origins.get(&connection).ok_or("origin")?;
    let acknowledgement = FederationFrame::OriginAck {
        edge_server_id: EDGE,
        server_incarnation: EDGE_INCARNATION,
        origin_id: origin.origin_id,
        generation: 0,
        object_id: Some(agenc_relay_federation_wire::FederationHash32::from_bytes(
            origin.object_id,
        )),
    };
    edge.handle_frame(fixture.context_mut()?, acknowledgement)
        .map_err(|violation| format!("the acknowledgement was refused: {violation:?}"))?;
    let origin = edge.origins.get_mut(&connection).ok_or("origin")?;
    assert_eq!(origin.acked_generation, Some(0));
    origin.sequence = EXECUTED;
    origin.session = Some((
        SessionId::from_bytes([41; 16]),
        UserId::from_bytes([42; 16]),
    ));
    edge.session_bound(fixture.context_mut()?, connection);
    Ok((edge, queue))
}

/// The origin frames the edge queued, in link order.
async fn origin_frames(queue: &mut LinkQueue) -> TestResult<Vec<FederationFrame>> {
    let mut frames = Vec::new();
    while let Ok(Some(line)) =
        tokio::time::timeout(std::time::Duration::from_millis(20), queue.recv()).await
    {
        let frame = parse_frame(line.as_str().trim_end_matches("\r\n"), EDGE_NAME)
            .map_err(|error| format!("{error:?}"))?;
        if matches!(
            frame,
            FederationFrame::OriginAdd { .. }
                | FederationFrame::OriginUpdate { .. }
                | FederationFrame::OriginDel { .. }
        ) {
            frames.push(frame);
        }
    }
    Ok(frames)
}

/// The coordinator's origin table after the generation-zero declaration
/// and the `EXECUTED` requests under it, with the link up.
fn coordinator_table(origin: &ConnectionOrigin) -> TestResult<(OriginTable, OriginKey)> {
    let key = OriginKey {
        home_server_id: EDGE,
        server_incarnation: EDGE_INCARNATION,
        origin_id: origin.origin_id,
    };
    let mut table = OriginTable::new();
    table.reset(EDGE, EDGE_INCARNATION);
    table.add(OriginDeclaration {
        origin: key,
        generation: 0,
        previous_object_id: [0; 32],
        binding: binding(origin),
        principal: OriginPrincipal::UNREGISTERED,
        object_id: origin.object_id,
    })?;
    table.ready(EDGE, EDGE_INCARNATION)?;
    for sequence in 0..EXECUTED {
        let operation = OperationKey {
            origin: key,
            generation: 0,
            sequence,
        };
        let request = RequestId::from_bytes([u8::try_from(sequence)?.wrapping_add(1); 16]);
        table.classify_request(operation, request, [1; 32], None)?;
        table.commit_request(operation, request)?;
    }
    Ok((table, key))
}

fn binding(origin: &ConnectionOrigin) -> OriginBinding {
    OriginBinding {
        connection_id: origin.connection_id,
        connection_nonce: origin.connection_nonce,
    }
}

/// Applies the UPDATE and DEL frames the edge sent after its acknowledged
/// declaration to the coordinator's table, in link order; `update` is the
/// record each UPDATE carries.
fn replay(
    table: &mut OriginTable,
    key: OriginKey,
    origin: &ConnectionOrigin,
    update: &agenc_relay_federation_wire::OriginRecord,
    frames: &[FederationFrame],
) -> TestResult<Option<(u64, u64)>> {
    let mut deleted = None;
    let mut updated = std::collections::BTreeSet::new();
    for frame in frames {
        match frame {
            FederationFrame::OriginUpdate { descriptor, .. }
                if updated.insert(descriptor.generation) =>
            {
                table.update(OriginDeclaration {
                    origin: key,
                    generation: descriptor.generation,
                    previous_object_id: update.previous_origin_object_id,
                    binding: binding(origin),
                    principal: OriginPrincipal {
                        session: update
                            .session
                            .map(|session| (session.session_id, session.user_id)),
                        account: None,
                    },
                    object_id: *descriptor.object_id.as_bytes(),
                })?;
            }
            FederationFrame::OriginDel {
                generation,
                next_operation_sequence,
                ..
            } => {
                table.delete(key, *generation, *next_operation_sequence)?;
                deleted = Some((*generation, *next_operation_sequence));
            }
            _ => {}
        }
    }
    Ok(deleted)
}

fn updates(frames: &[FederationFrame]) -> usize {
    frames
        .iter()
        .filter(|frame| matches!(frame, FederationFrame::OriginUpdate { .. }))
        .count()
}

#[tokio::test]
async fn a_deletion_names_the_acknowledged_generation_until_the_update_is_sent() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let connection = ConnectionGeneration::new(1);
    let (mut edge, mut queue) = bound(&mut fixture, connection).await?;
    let _declared = origin_frames(&mut queue).await?;
    let origin = edge.origins.get(&connection).ok_or("origin")?;
    let update = origin.pending_updates.front().copied().ok_or("update")?;
    assert!(
        edge.commit.is_some(),
        "the update waits for its journal write"
    );
    let (mut table, key) = coordinator_table(origin)?;
    edge.connection_closed(fixture.context_mut()?, connection, "");
    commit_edge_batches(&mut edge, &mut fixture).await?;
    let frames = origin_frames(&mut queue).await?;
    let origin = edge.origins.get(&connection).ok_or("origin")?;
    assert_eq!(updates(&frames), 0, "the closed origin declares nothing");
    assert_eq!(
        replay(&mut table, key, origin, &update, &frames)?,
        Some((0, EXECUTED)),
        "the deletion names the acknowledged generation: {}",
        frames.len()
    );
    Ok(())
}

#[tokio::test]
async fn a_deletion_names_the_update_the_link_carried() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let connection = ConnectionGeneration::new(1);
    let (mut edge, mut queue) = bound(&mut fixture, connection).await?;
    let origin = edge.origins.get(&connection).ok_or("origin")?;
    let update = origin.pending_updates.front().copied().ok_or("update")?;
    let (mut table, key) = coordinator_table(origin)?;
    commit_edge_batches(&mut edge, &mut fixture).await?;
    edge.connection_closed(fixture.context_mut()?, connection, "");
    commit_edge_batches(&mut edge, &mut fixture).await?;
    let frames = origin_frames(&mut queue).await?;
    let origin = edge.origins.get(&connection).ok_or("origin")?;
    assert!(updates(&frames) > 0, "the update was sent before the close");
    assert_eq!(
        replay(&mut table, key, origin, &update, &frames)?,
        Some((1, 0)),
        "the deletion names the generation of the update in flight"
    );
    Ok(())
}

#[tokio::test]
async fn a_deletion_after_an_acknowledged_update_names_that_generation() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let connection = ConnectionGeneration::new(1);
    let (mut edge, mut queue) = bound(&mut fixture, connection).await?;
    commit_edge_batches(&mut edge, &mut fixture).await?;
    let origin = edge.origins.get(&connection).ok_or("origin")?;
    let update = origin.pending_updates.front().copied().ok_or("update")?;
    let (mut table, key) = coordinator_table(origin)?;
    let sent = origin_frames(&mut queue).await?;
    assert!(replay(&mut table, key, origin, &update, &sent)?.is_none());
    let encoded = update.to_object()?.encode_canonical()?;
    let acknowledgement = FederationFrame::OriginAck {
        edge_server_id: EDGE,
        server_incarnation: EDGE_INCARNATION,
        origin_id: update.origin_id,
        generation: update.generation,
        object_id: Some(federation_object_id(encoded.as_slice())),
    };
    edge.handle_frame(fixture.context_mut()?, acknowledgement)
        .map_err(|violation| format!("the acknowledgement was refused: {violation:?}"))?;
    // The login after registration queues the next update, which waits for
    // its journal write when the connection ends.
    let origin = edge.origins.get_mut(&connection).ok_or("origin")?;
    origin.account = Some((agenc_relay_testkit::account_id(5), 1));
    assert!(origin.pending_updates.is_empty());
    edge.session_bound(fixture.context_mut()?, connection);
    edge.connection_closed(fixture.context_mut()?, connection, "");
    commit_edge_batches(&mut edge, &mut fixture).await?;
    let frames = origin_frames(&mut queue).await?;
    let origin = edge.origins.get(&connection).ok_or("origin")?;
    assert_eq!(updates(&frames), 0, "the second update was never sent");
    assert_eq!(
        replay(&mut table, key, origin, &update, &frames)?,
        Some((1, 0)),
        "the deletion names the acknowledged generation"
    );
    Ok(())
}

/// After a link loss a closed connection's origin replays only its
/// deletion, which names the generation of the update the first link
/// carried (spec 20.7): the edge keeps, across the link loss, its record
/// that the update went out, since the next link replays no declaration for
/// a deleted origin. The coordinator, ready again with the origin already
/// deleted, accepts only the exact generation and next sequence it holds,
/// so the replayed deletion must name what the first one did.
#[tokio::test]
async fn a_relinked_deletion_names_the_update_the_first_link_carried() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let connection = ConnectionGeneration::new(1);
    let (mut edge, mut queue) = bound(&mut fixture, connection).await?;
    let origin = edge.origins.get(&connection).ok_or("origin")?;
    let update = origin.pending_updates.front().copied().ok_or("update")?;
    let (mut table, key) = coordinator_table(origin)?;
    // The first link carries the update and then the deletion; the
    // coordinator commits both.
    commit_edge_batches(&mut edge, &mut fixture).await?;
    edge.connection_closed(fixture.context_mut()?, connection, "");
    commit_edge_batches(&mut edge, &mut fixture).await?;
    let frames = origin_frames(&mut queue).await?;
    let origin = edge.origins.get(&connection).ok_or("origin")?;
    assert_eq!(
        replay(&mut table, key, origin, &update, &frames)?,
        Some((1, 0)),
        "the first deletion names the update the link carried"
    );
    // The link is lost before either acknowledgement arrives, and the
    // coordinator turns ready again with the origin already deleted.
    let link = edge.live.as_ref().ok_or("live link")?.link;
    edge.link_closed(fixture.context_mut()?, link);
    table.link_lost(
        EDGE,
        EDGE_INCARNATION,
        agenc_relay_types::MonotonicTick::from_ticks(1),
    )?;
    table.reset(EDGE, EDGE_INCARNATION);
    table.ready(EDGE, EDGE_INCARNATION)?;
    // The edge relinks and replays the closed origin: only its deletion,
    // naming the same generation as the first link, which the ready
    // coordinator accepts as the exact deletion it holds.
    let mut relinked = resync_snapshot_link(&mut edge);
    edge.phase = Phase::Origins;
    request::replay_origin(&mut edge, fixture.context_mut()?, connection);
    let frames = origin_frames(&mut relinked).await?;
    let origin = edge.origins.get(&connection).ok_or("origin")?;
    assert_eq!(
        replay(&mut table, key, origin, &update, &frames)?,
        Some((1, 0)),
        "the replayed deletion names the generation the first link carried"
    );
    Ok(())
}
