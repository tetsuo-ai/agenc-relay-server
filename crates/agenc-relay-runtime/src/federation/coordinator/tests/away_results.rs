#![forbid(unsafe_code)]

//! AWAY acknowledgments are durable, covered, and replayed without a new event.

use super::*;
use crate::federation::codec::results::{ReplyParts, reply_parts_of};

fn replies(answer: &Answer) -> TestResult<Vec<ReplyParts>> {
    let object = SchemaObject::decode_exact(
        "FederationResult",
        &answer.bytes,
        &mut DecodeBudget::new(1 << 20, 4096),
    )?;
    agenc_relay_federation_wire::access::vector(&object, "replies")?
        .iter()
        .map(reply_parts_of)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn away_answer(edge: &mut Edge, origin: &mut Origin) -> TestResult<Answer> {
    let mut events = Vec::new();
    let result = answer(edge, &mut events).await?;
    let completion = result
        .header
        .completion_event_id
        .ok_or("no covering event")?;
    while !events
        .iter()
        .any(|(header, _)| header.event_id == completion)
    {
        events.push(next_event(edge).await?);
    }
    assert!(
        events
            .iter()
            .any(|(_, event)| { matches!(event, ProjectedEvent::AwayChanged { .. }) })
    );
    origin.sequence += 1;
    Ok(result)
}

#[tokio::test]
async fn away_results_cover_changes_and_replay_exactly() -> TestResult {
    let identity = peer_identity(ServerId::from_bytes([75; 16]), "edge.example");
    run_coordinator(&[identity], |inbox| async move {
        let mut edge = Edge::new(inbox, 75);
        let mut origin = Origin::new(96);
        edge.establish().await?;
        synchronize_ok(&mut edge, &mut [&mut origin]).await?;
        let mut events = Vec::new();
        let (session, _, revision) =
            open_session(&mut edge, &mut origin, "atlas", &mut events).await?;
        let bytes = request(
            &mut edge,
            &mut origin,
            &FederatedOperation::Away {
                session_id: session,
                expected_session_revision: revision,
                away_text: "account deletion pending".to_owned(),
            },
        )
        .await?;
        let marked = away_answer(&mut edge, &mut origin).await?;
        assert_eq!(
            replies(&marked)?,
            vec![ReplyParts {
                command: "306".to_owned(),
                parameters: vec!["atlas".to_owned()],
                trailing: Some("You have been marked as being away".to_owned()),
            }]
        );
        let header = RequestHeader::from_object(&SchemaObject::decode_exact(
            "FederationRequest",
            &bytes,
            &mut DecodeBudget::new(1 << 20, 4096),
        )?)?;
        send_request(&mut edge, &header, &bytes).await?;
        let mut replay_events = Vec::new();
        let replay = answer(&mut edge, &mut replay_events).await?;
        assert_eq!(replay.bytes, marked.bytes);
        assert!(replay_events.is_empty());
        let ResultArm::Committed {
            resulting_state_generation,
        } = marked.arm
        else {
            return Err("AWAY did not commit".into());
        };
        request(
            &mut edge,
            &mut origin,
            &FederatedOperation::Away {
                session_id: session,
                expected_session_revision: resulting_state_generation,
                away_text: String::new(),
            },
        )
        .await?;
        let cleared = away_answer(&mut edge, &mut origin).await?;
        assert_eq!(
            replies(&cleared)?,
            vec![ReplyParts {
                command: "305".to_owned(),
                parameters: vec!["atlas".to_owned()],
                trailing: Some("You are no longer marked as being away".to_owned()),
            }]
        );
        Ok(())
    })
    .await
}
