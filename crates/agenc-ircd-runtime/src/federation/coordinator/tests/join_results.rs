//! JOIN results retain exact topic replies and target-local failures.

#![forbid(unsafe_code)]

use super::*;
use crate::federation::codec::results::{ReplyParts, reply_parts_of};

fn reply_parts(answer: &Answer) -> TestResult<Vec<ReplyParts>> {
    let result = SchemaObject::decode_exact(
        "FederationResult",
        &answer.bytes,
        &mut DecodeBudget::new(1 << 20, 4096),
    )?;
    agenc_ircd_federation_wire::access::vector(&result, "replies")?
        .iter()
        .map(reply_parts_of)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn covered_answer(edge: &mut Edge, origin: &mut Origin) -> TestResult<Answer> {
    let mut events = Vec::new();
    let result = answer(edge, &mut events).await?;
    assert_eq!(result.header.result_kind, FederationResultKind::Committed);
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
    origin.sequence += 1;
    Ok(result)
}

fn join_request(session_id: SessionId, revision: u64, names: &[&str]) -> FederatedOperation {
    FederatedOperation::Join {
        session_id,
        expected_session_revision: revision,
        targets: names
            .iter()
            .map(|name| JoinTarget {
                channel_name: (*name).to_owned(),
                join_key: zeroize::Zeroizing::new(Vec::new()),
            })
            .collect(),
    }
}

#[tokio::test]
async fn join_results_replay_topics_and_preserve_partial_failures() -> TestResult {
    let identity = peer_identity(ServerId::from_bytes([74; 16]), "edge.example");
    run_coordinator(&[identity], |inbox| async move {
        let mut edge = Edge::new(inbox, 74);
        let mut first = Origin::new(94);
        let mut second = Origin::new(95);
        edge.establish().await?;
        synchronize_ok(&mut edge, &mut [&mut first, &mut second]).await?;
        let mut events = Vec::new();
        let (first_session, _, first_revision) =
            open_session(&mut edge, &mut first, "june", &mut events).await?;
        let (second_session, _, second_revision) =
            open_session(&mut edge, &mut second, "jules", &mut events).await?;
        let request_bytes = request(
            &mut edge,
            &mut first,
            &join_request(first_session, first_revision, &["#topic"]),
        )
        .await?;
        let created = covered_answer(&mut edge, &mut first).await?;
        assert_eq!(
            reply_parts(&created)?,
            vec![ReplyParts {
                command: "331".to_owned(),
                parameters: vec!["june".to_owned(), "#topic".to_owned()],
                trailing: Some("No topic is set".to_owned()),
            }]
        );
        let header = RequestHeader::from_object(&SchemaObject::decode_exact(
            "FederationRequest",
            &request_bytes,
            &mut DecodeBudget::new(1 << 20, 4096),
        )?)?;
        send_request(&mut edge, &header, &request_bytes).await?;
        let mut replay_events = Vec::new();
        let replay = answer(&mut edge, &mut replay_events).await?;
        assert_eq!(replay.bytes, created.bytes);
        assert!(replay_events.is_empty());
        let channel_id = *edge
            .channel_revisions
            .keys()
            .next()
            .ok_or("missing channel")?;
        let channel_revision = events_b_channel_revision(&mut edge, channel_id).await?;
        request(
            &mut edge,
            &mut first,
            &FederatedOperation::Topic {
                session_id: first_session,
                channel_id,
                expected_channel_revision: channel_revision,
                topic: "preserved topic".to_owned(),
            },
        )
        .await?;
        covered_answer(&mut edge, &mut first).await?;
        request(
            &mut edge,
            &mut second,
            &join_request(second_session, second_revision, &["#empty", "#topic"]),
        )
        .await?;
        let joined = covered_answer(&mut edge, &mut second).await?;
        let replies = reply_parts(&joined)?;
        assert_eq!(
            replies
                .iter()
                .map(|reply| reply.command.as_str())
                .collect::<Vec<_>>(),
            ["331", "332", "333"]
        );
        let [empty, topic, metadata] = replies.as_slice() else {
            return Err("expected all three topic replies".into());
        };
        assert_eq!(empty.parameters, ["jules", "#empty"]);
        assert_eq!(topic.parameters, ["jules", "#topic"]);
        assert_eq!(topic.trailing.as_deref(), Some("preserved topic"));
        let [requester, channel, setter, set_at] = metadata.parameters.as_slice() else {
            return Err("expected exact topic metadata".into());
        };
        assert_eq!(
            [requester.as_str(), channel.as_str(), setter.as_str()],
            ["jules", "#topic", "june"]
        );
        assert!(set_at.parse::<u64>().is_ok());
        let ResultArm::Committed {
            resulting_state_generation,
        } = created.arm
        else {
            return Err("missing membership revision".into());
        };
        request(
            &mut edge,
            &mut first,
            &join_request(
                first_session,
                resulting_state_generation,
                &["#fresh", "#topic"],
            ),
        )
        .await?;
        let partial = covered_answer(&mut edge, &mut first).await?;
        let replies = reply_parts(&partial)?;
        assert_eq!(
            replies
                .iter()
                .map(|reply| reply.command.as_str())
                .collect::<Vec<_>>(),
            ["331", "482"]
        );
        let [accepted, refused] = replies.as_slice() else {
            return Err("expected accepted and refused JOIN replies".into());
        };
        assert_eq!(accepted.parameters, ["june", "#fresh"]);
        assert_eq!(refused.parameters, ["june", "#topic"]);
        Ok(())
    })
    .await
}
