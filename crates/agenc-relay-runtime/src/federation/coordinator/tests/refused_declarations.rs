#![forbid(unsafe_code)]

//! A FORIGIN UPDATE naming a session or account the coordinator removed
//! after the edge's link carried it is refused for that origin alone
//! (Architecture 20.7): nothing is acknowledged, the origin closes at the
//! generation and next sequence it holds with the sessions it owns, the
//! link stays up, and the edge's deletion naming the refused generation is
//! acknowledged.

use agenc_relay_federation_wire::OriginAccount;
use agenc_relay_types::{AccountId, AccountRandomId};

use super::*;

mod restart;

/// Sends one declaration of `record` without waiting for its answer.
async fn send_declaration(edge: &mut Edge, record: &OriginRecord, update: bool) -> TestResult {
    let encoded = record.to_object()?.encode_canonical()?;
    let bytes = encoded.as_slice().to_vec();
    let descriptor = OriginDescriptor {
        coordinator_server_id: COORDINATOR,
        server_incarnation: edge.incarnation,
        origin_id: record.origin_id,
        generation: record.generation,
        object_id: federation_object_id(&bytes),
    };
    edge.object(&bytes, |fragment| {
        if update {
            FederationFrame::OriginUpdate {
                descriptor,
                fragment,
            }
        } else {
            FederationFrame::OriginAdd {
                descriptor,
                fragment,
            }
        }
    })
    .await
}

/// Registers a session for `origin` and returns its identity, without
/// declaring it.
async fn register(
    edge: &mut Edge,
    origin: &mut Origin,
    nickname: &str,
) -> TestResult<(SessionId, UserId)> {
    let mut events = Vec::new();
    request(
        edge,
        origin,
        &session_open(origin.id.as_bytes()[0], nickname),
    )
    .await?;
    let answer = answer(edge, &mut events).await?;
    let ResultArm::SessionRegistered(registered) = answer.arm else {
        return Err("registration refused".into());
    };
    origin.sequence += 1;
    Ok((registered.session_id, registered.user_id))
}

/// Closes `session` through `origin`, as its connection's end does.
async fn close_session(edge: &mut Edge, origin: &mut Origin, session: SessionId) -> TestResult {
    request(
        edge,
        origin,
        &FederatedOperation::SessionClose {
            session_id: session,
            reason_code: 2,
        },
    )
    .await?;
    let closed = answer(edge, &mut Vec::new()).await?;
    if closed.header.result_kind != FederationResultKind::Committed {
        return Err("the session close was refused".into());
    }
    origin.sequence += 1;
    Ok(())
}

/// Declares a fresh origin and requires its acknowledgement to be the next
/// acknowledgement on the link: the link is up, and nothing acknowledged the
/// refused declaration before it.
async fn still_answers(edge: &mut Edge, seed: u8) -> TestResult {
    declare(edge, &mut Origin::new(seed), false)
        .await
        .map(|_| ())
}

/// Sends the edge's deletion of `origin` at `generation` and sequence zero
/// and requires its acknowledgement.
async fn delete_refused(edge: &mut Edge, origin: &Origin, generation: u64) -> TestResult {
    edge.frame(FederationFrame::OriginDel {
        coordinator_server_id: COORDINATOR,
        server_incarnation: edge.incarnation,
        origin_id: origin.id,
        generation,
        next_operation_sequence: 0,
    })
    .await?;
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

#[tokio::test]
async fn a_declaration_naming_a_removed_session_closes_only_its_origin() -> TestResult {
    let identity = peer_identity(ServerId::from_bytes([51; 16]), "edge.example");
    run_coordinator(&[identity], |inbox| async move {
        let mut edge = Edge::new(inbox, 51);
        let mut origin = Origin::new(71);
        let mut other = Origin::new(72);
        edge.establish().await?;
        synchronize_ok(&mut edge, &mut [&mut origin, &mut other]).await?;
        // The origin's registration commits, and its session is removed
        // before the edge's declaration of it arrives.
        let (session, user) = register(&mut edge, &mut origin, "nora").await?;
        close_session(&mut edge, &mut origin, session).await?;
        origin.session = Some((session, user));
        origin.advance_generation();
        let record = origin.record(&edge);
        send_declaration(&mut edge, &record, true).await?;
        // Nothing is acknowledged, and the link keeps serving the edge.
        still_answers(&mut edge, 73).await?;
        delete_refused(&mut edge, &origin, origin.generation).await?;
        register(&mut edge, &mut other, "omar").await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_declaration_naming_an_account_its_session_lacks_closes_that_session() -> TestResult {
    let identity = peer_identity(ServerId::from_bytes([52; 16]), "edge.example");
    run_coordinator(&[identity], |inbox| async move {
        let mut edge = Edge::new(inbox, 52);
        let mut origin = Origin::new(74);
        let mut other = Origin::new(75);
        edge.establish().await?;
        synchronize_ok(&mut edge, &mut [&mut origin, &mut other]).await?;
        let (_, user, _) = open_session(&mut edge, &mut origin, "quinn", &mut Vec::new()).await?;
        // The next generation names an account the live session is not
        // authenticated as.
        origin.advance_generation();
        let mut record = origin.record(&edge);
        record.account = Some(OriginAccount {
            account_id: AccountId::from_random(AccountRandomId::from_bytes([76; 16])),
            account_session_generation: 1,
        });
        send_declaration(&mut edge, &record, true).await?;
        // The refusal closes the origin with the session it owns.
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let (_, event) = next_event(&mut edge).await?;
                if let ProjectedEvent::SessionHidden { source, .. } = event
                    && source.user_id == user
                {
                    return Ok::<(), Box<dyn Error>>(());
                }
            }
        })
        .await
        .map_err(|_| "the refused origin's session stayed visible")??;
        still_answers(&mut edge, 79).await?;
        delete_refused(&mut edge, &origin, origin.generation).await?;
        register(&mut edge, &mut other, "rosa").await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_refused_declaration_replayed_on_the_next_link_is_refused_again() -> TestResult {
    let identity = peer_identity(ServerId::from_bytes([53; 16]), "edge.example");
    run_coordinator(&[identity], |inbox| async move {
        let mut edge = Edge::new(inbox, 53);
        let mut origin = Origin::new(77);
        let mut other = Origin::new(78);
        edge.establish().await?;
        synchronize_ok(&mut edge, &mut [&mut origin, &mut other]).await?;
        let (session, user) = register(&mut edge, &mut origin, "sami").await?;
        close_session(&mut edge, &mut origin, session).await?;
        origin.session = Some((session, user));
        origin.advance_generation();
        let record = origin.record(&edge);
        send_declaration(&mut edge, &record, true).await?;
        let mut fresh = Origin::new(80);
        declare(&mut edge, &mut fresh, false).await?;
        // The link is lost before the connection ends. The next link
        // replays the other origin and the refused declaration; the closed
        // origin does not hold READY back.
        edge.close().await?;
        edge.establish().await?;
        let cursor = match edge.last_ack {
            Some((delivery_sequence, event_id)) => {
                agenc_relay_federation_wire::DeliveryCursor::At {
                    delivery_sequence,
                    event_id,
                }
            }
            None => agenc_relay_federation_wire::DeliveryCursor::Empty,
        };
        edge.frame(FederationFrame::Resume {
            coordinator_server_id: COORDINATOR,
            projection_generation: edge.projection_generation,
            cursor,
        })
        .await?;
        let resumed = edge.next_wire_frame().await?;
        if !matches!(resumed, FederationFrame::ResumeOk { .. }) {
            return Err(format!("expected FRESUME OK, got {:?}", resumed.kind()).into());
        }
        edge.frame(FederationFrame::OriginReset {
            coordinator_server_id: COORDINATOR,
            server_incarnation: edge.incarnation,
        })
        .await?;
        let update = other.generation > 0;
        let mut ready = declare(&mut edge, &mut other, update).await?;
        ready |= declare(&mut edge, &mut fresh, false).await?;
        let record = origin.record(&edge);
        send_declaration(&mut edge, &record, true).await?;
        while !ready {
            match edge.next_wire_frame().await? {
                FederationFrame::OriginReady { .. } => ready = true,
                FederationFrame::Event { .. } => {}
                other => {
                    return Err(format!("expected READY, got {:?}", other.kind()).into());
                }
            }
        }
        delete_refused(&mut edge, &origin, origin.generation).await?;
        register(&mut edge, &mut other, "uma").await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_malformed_declaration_naming_a_removed_session_is_still_a_violation() -> TestResult {
    let identity = peer_identity(ServerId::from_bytes([54; 16]), "edge.example");
    run_coordinator(&[identity], |inbox| async move {
        let mut edge = Edge::new(inbox, 54);
        let mut origin = Origin::new(81);
        edge.establish().await?;
        synchronize_ok(&mut edge, &mut [&mut origin]).await?;
        let (session, user) = register(&mut edge, &mut origin, "vera").await?;
        close_session(&mut edge, &mut origin, session).await?;
        origin.session = Some((session, user));
        // The declaration skips a generation: the origin table's checks run
        // before its removed session is classified.
        origin.advance_generation();
        origin.advance_generation();
        let record = origin.record(&edge);
        send_declaration(&mut edge, &record, true).await?;
        edge.expect_closed().await
    })
    .await
}
