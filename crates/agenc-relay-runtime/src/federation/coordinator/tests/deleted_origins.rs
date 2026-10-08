#![forbid(unsafe_code)]

//! A deletion of an origin this coordinator already deleted, on a ready
//! link, is acknowledged when it names exactly the generation and next
//! sequence the coordinator holds, or the next generation at sequence zero:
//! the edge's pending update, an update this coordinator never committed,
//! whether or not a link carried it, under which nothing ran. Nothing changes,
//! and the link keeps serving the edge. Any other deletion of the origin
//! still closes the link (Architecture 20.5, 20.7).

use super::*;

/// Runs one session open under `origin`'s generation zero, without the
/// update a registration declares next.
async fn run_one_request(edge: &mut Edge, origin: &mut Origin, nickname: &str) -> TestResult {
    request(
        edge,
        origin,
        &session_open(origin.id.as_bytes()[0], nickname),
    )
    .await?;
    let answered = answer(edge, &mut Vec::new()).await?;
    if !matches!(answered.arm, ResultArm::SessionRegistered(_)) {
        return Err("the session open was refused".into());
    }
    origin.sequence += 1;
    Ok(())
}

/// Sends the edge's deletion of `origin` naming `generation` and
/// `next_sequence`, and requires its acknowledgement at that generation.
async fn deleted(
    edge: &mut Edge,
    origin: &Origin,
    generation: u64,
    next_sequence: u64,
) -> TestResult {
    send_deletion(edge, origin, generation, next_sequence).await?;
    loop {
        match edge.next_frame().await? {
            FederationFrame::OriginAck {
                origin_id,
                generation: acked,
                object_id: None,
                ..
            } if origin_id == origin.id && acked == generation => return Ok(()),
            FederationFrame::Event { .. } => {}
            other => {
                return Err(format!("expected the deletion's ACK, got {:?}", other.kind()).into());
            }
        }
    }
}

async fn send_deletion(
    edge: &mut Edge,
    origin: &Origin,
    generation: u64,
    next_sequence: u64,
) -> TestResult {
    edge.frame(FederationFrame::OriginDel {
        coordinator_server_id: COORDINATOR,
        server_incarnation: edge.incarnation,
        origin_id: origin.id,
        generation,
        next_operation_sequence: next_sequence,
    })
    .await
}

/// The origin is deleted at generation zero after one request; the link is
/// lost before the acknowledgement reaches the edge, and the next link,
/// with only deleted origins left, is ready at its reset.
async fn deleted_then_relinked(edge: &mut Edge, origin: &mut Origin, nickname: &str) -> TestResult {
    edge.establish().await?;
    synchronize_ok(edge, &mut [&mut *origin]).await?;
    run_one_request(edge, origin, nickname).await?;
    deleted(edge, origin, 0, 1).await?;
    edge.close().await?;
    edge.establish().await?;
    synchronize_ok(edge, &mut []).await
}

#[tokio::test]
async fn a_deletion_naming_the_update_a_deleted_origin_never_committed_is_acknowledged()
-> TestResult {
    let identity = peer_identity(ServerId::from_bytes([56; 16]), "edge.example");
    run_coordinator(&[identity], |inbox| async move {
        let mut edge = Edge::new(inbox, 56);
        let mut origin = Origin::new(84);
        deleted_then_relinked(&mut edge, &mut origin, "wren").await?;
        // The edge's deletion names the update it queued before the
        // connection ended, an update the coordinator never committed,
        // whether or not a link carried it.
        deleted(&mut edge, &origin, 1, 0).await?;
        // The deletion the coordinator holds is unchanged: its exact form is
        // still the one acknowledged, and the link keeps serving the edge.
        deleted(&mut edge, &origin, 0, 1).await?;
        declare(&mut edge, &mut Origin::new(85), false).await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn any_other_deletion_of_a_deleted_origin_still_closes_the_link() -> TestResult {
    for (seed, generation, next_sequence) in [(57, 1, 1), (58, 2, 0), (59, 0, 2), (60, 0, 0)] {
        let identity = peer_identity(ServerId::from_bytes([seed; 16]), "edge.example");
        run_coordinator(&[identity], |inbox| async move {
            let mut edge = Edge::new(inbox, seed);
            let mut origin = Origin::new(seed.wrapping_add(30));
            deleted_then_relinked(&mut edge, &mut origin, "yara").await?;
            send_deletion(&mut edge, &origin, generation, next_sequence).await?;
            edge.expect_closed().await
        })
        .await?;
    }
    Ok(())
}
