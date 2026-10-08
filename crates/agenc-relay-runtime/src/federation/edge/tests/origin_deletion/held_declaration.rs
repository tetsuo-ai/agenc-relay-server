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
