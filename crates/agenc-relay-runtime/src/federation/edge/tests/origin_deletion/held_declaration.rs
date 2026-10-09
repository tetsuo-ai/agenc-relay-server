#![forbid(unsafe_code)]

//! Every declaration of an origin's held generation is the object the
//! coordinator acknowledged at it (spec 20.7: `UPDATE` names the exact
//! previous object). A connection's session and account move to a new
//! principal as soon as it is known, before its update is queued; until the
//! update is queued and acknowledged, the origin's journal row and a
//! declaration a new link replays still name the held generation's
//! principal.

use super::*;

#[tokio::test]
async fn a_declaration_of_the_held_generation_names_the_acknowledged_object() -> TestResult {
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let connection = ConnectionGeneration::new(1);
    let mut edge = resync_edge();
    let mut queue = resync_snapshot_link(&mut edge);
    edge.phase = Phase::Active;
    edge.connection_opened(fixture.context_mut()?, connection);
    commit_edge_batches(&mut edge, &mut fixture).await?;
    let origin = edge.origins.get(&connection).ok_or("origin")?;
    let acknowledged = origin.object_id;
    edge.handle_frame(
        fixture.context_mut()?,
        FederationFrame::OriginAck {
            edge_server_id: EDGE,
            server_incarnation: EDGE_INCARNATION,
            origin_id: origin.origin_id,
            generation: 0,
            object_id: Some(agenc_relay_federation_wire::FederationHash32::from_bytes(
                acknowledged,
            )),
        },
    )
    .map_err(|violation| format!("the acknowledgement was refused: {violation:?}"))?;
    let _declared = origin_frames(&mut queue).await?;
    // The registration completed: the connection's session is known, and
    // its update is not queued yet.
    let origin = edge.origins.get_mut(&connection).ok_or("origin")?;
    origin.session = Some((
        SessionId::from_bytes([41; 16]),
        UserId::from_bytes([42; 16]),
    ));
    let row =
        journal::origin_record(&edge, connection).map_err(|violation| format!("{violation:?}"))?;
    assert_eq!(
        row.origin_object_id, acknowledged,
        "the row holds the acknowledged object"
    );
    // A new link replays the origin's current declaration.
    request::replay_origin(&mut edge, fixture.context_mut()?, connection);
    commit_edge_batches(&mut edge, &mut fixture).await?;
    let replayed: Vec<_> = origin_frames(&mut queue)
        .await?
        .into_iter()
        .filter_map(|frame| match frame {
            FederationFrame::OriginAdd { descriptor, .. }
            | FederationFrame::OriginUpdate { descriptor, .. } => {
                Some((descriptor.generation, *descriptor.object_id.as_bytes()))
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        replayed,
        [(0, acknowledged)],
        "the replayed declaration is the acknowledged object"
    );
    let origin = edge.origins.get(&connection).ok_or("origin")?;
    assert_eq!(origin.object_id, acknowledged);
    Ok(())
}

/// The companion declaration of a generation mirrors the base declaration
/// of that generation (companion 12.5): the base facts it is built from name
/// the principal the acknowledged declaration named, not the connection's
/// next principal while its update waits, and the update's own principal
/// once it is acknowledged.
#[tokio::test]
async fn the_companion_facts_of_the_held_generation_name_its_acknowledged_principal() -> TestResult
{
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let connection = ConnectionGeneration::new(1);
    let mut edge = resync_edge();
    let mut queue = resync_snapshot_link(&mut edge);
    edge.phase = Phase::Active;
    edge.connection_opened(fixture.context_mut()?, connection);
    commit_edge_batches(&mut edge, &mut fixture).await?;
    let origin = edge.origins.get(&connection).ok_or("origin")?;
    edge.handle_frame(
        fixture.context_mut()?,
        FederationFrame::OriginAck {
            edge_server_id: EDGE,
            server_incarnation: EDGE_INCARNATION,
            origin_id: origin.origin_id,
            generation: 0,
            object_id: Some(agenc_relay_federation_wire::FederationHash32::from_bytes(
                origin.object_id,
            )),
        },
    )
    .map_err(|violation| format!("the acknowledgement was refused: {violation:?}"))?;
    let _declared = origin_frames(&mut queue).await?;
    // The registration completed, with a login before it: the connection's
    // session and account are known, and its update is not queued yet.
    let session = (
        SessionId::from_bytes([41; 16]),
        UserId::from_bytes([42; 16]),
    );
    let account = agenc_relay_testkit::account_id(5);
    let origin = edge.origins.get_mut(&connection).ok_or("origin")?;
    origin.session = Some(session);
    origin.account = Some((account, 1));
    let facts = edge.origin_facts(connection).ok_or("facts")?;
    assert_eq!(facts.acked_generation, Some(0));
    assert_eq!(
        (facts.session, facts.account),
        (None, None),
        "generation zero is the unregistered principal"
    );
    // The update is queued, carried and acknowledged: generation one names
    // the session and account.
    edge.session_bound(fixture.context_mut()?, connection);
    commit_edge_batches(&mut edge, &mut fixture).await?;
    let update = edge
        .origins
        .get(&connection)
        .ok_or("origin")?
        .pending_updates
        .front()
        .copied()
        .ok_or("update")?;
    assert_eq!(
        edge.origin_facts(connection)
            .ok_or("facts")?
            .acked_generation,
        None,
        "nothing is mirrored while the update waits"
    );
    let encoded = update.to_object()?.encode_canonical()?;
    edge.handle_frame(
        fixture.context_mut()?,
        FederationFrame::OriginAck {
            edge_server_id: EDGE,
            server_incarnation: EDGE_INCARNATION,
            origin_id: update.origin_id,
            generation: update.generation,
            object_id: Some(federation_object_id(encoded.as_slice())),
        },
    )
    .map_err(|violation| format!("the update was refused: {violation:?}"))?;
    let facts = edge.origin_facts(connection).ok_or("facts")?;
    let account_text: [u8; 24] = account.to_text().as_bytes().try_into()?;
    assert_eq!(facts.acked_generation, Some(1));
    assert_eq!(
        (facts.session, facts.account),
        (
            Some((*session.0.as_bytes(), *session.1.as_bytes())),
            Some((account_text, 1)),
        )
    );
    Ok(())
}
