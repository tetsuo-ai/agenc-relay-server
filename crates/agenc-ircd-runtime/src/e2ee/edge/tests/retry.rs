#![forbid(unsafe_code)]

//! Reply reuse preserves the requester, command, completion, and retention bounds.

use super::*;
use crate::test_support::StateCoreFixture;

#[test]
fn a_reply_is_cached_only_after_completion_and_cannot_cross_routes() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let mut edge = edge();
    let mut request = pending(1, 3, true);
    let key = (1, 0, [9; 32], [7; 32]);
    let command = request.command.clone();
    request.reply_key = Some(key);
    request.label = Some("first".to_owned());
    request.result.as_mut().ok_or("result")?.completion_event_id = Some([6; 16]);
    edge.pending.insert([5; 16], request);
    assert!(
        edge.render_ready(fixture.context_mut()?, [5; 16])
            .map_err(|e| e.code.to_string())?
            .is_empty()
    );
    assert!(
        edge.replies
            .replay(key, &command, Some("retry"))
            .map_err(|e| e.code.to_string())?
            .is_none()
    );
    edge.pending
        .get_mut(&[5; 16])
        .ok_or("pending")?
        .completion_seen = true;
    assert_eq!(
        edge.render_ready(fixture.context_mut()?, [5; 16])
            .map_err(|e| e.code.to_string())?
            .len(),
        1
    );
    let replay = edge
        .replies
        .replay(key, &command, Some("retry"))
        .map_err(|e| e.code.to_string())?
        .ok_or("reply")?;
    assert_eq!(replay.generation, ConnectionGeneration::new(1));
    // Compare tags and body against the same protocol refusal renderer.
    let body = agenc_ircd_e2ee::wire::reply::E2eeReplyCode::Syncing.render_fail("EDIRECT", None);
    let line =
        agenc_ircd_e2ee::wire::response::render_labeled_fail("retry", "edge.example", &body)?;
    assert_eq!(
        replay.frames,
        vec![agenc_ircd_client_wire::WireMessage::extension_line(&line)?]
    );
    let other = Resolved::Command(ClientCommand::Edirect([8; 32]));
    assert!(edge.replies.replay(key, &other, None).is_err());
    assert!(
        edge.replies
            .replay((2, 0, [9; 32], [7; 32]), &command, None)
            .map_err(|e| e.code.to_string())?
            .is_none()
    );
    assert!(
        edge.replies
            .replay((1, 1, [9; 32], [7; 32]), &command, None)
            .map_err(|e| e.code.to_string())?
            .is_none()
    );
    edge.connection_closed(ConnectionGeneration::new(1));
    assert!(
        edge.replies
            .replay(key, &command, None)
            .map_err(|e| e.code.to_string())?
            .is_none()
    );
    Ok(())
}

#[test]
fn reply_retention_and_outstanding_reservations_are_bounded() -> TestResult {
    let mut replies = super::super::retry::Replies::default();
    assert!(replies.admits(0));
    assert!(!replies.admits(usize::MAX));
    assert!(!replies.admits(8));
    let mut request = pending(1, 0, true);
    request.reply_key = Some((1, 0, [9; 32], [7; 32]));
    replies
        .remember(
            &request,
            vec![":edge.example EKEY STORED IDENTITY test".to_owned()],
            5,
        )
        .map_err(|e| e.code.to_string())?;
    let until = 5 + agenc_ircd_e2ee::limits::RECENT_OBJECT_IDEMPOTENCY_RETENTION_SECONDS;
    replies.expire(until - 1);
    assert!(
        replies
            .replay((1, 0, [9; 32], [7; 32]), &request.command, None)
            .map_err(|e| e.code.to_string())?
            .is_some()
    );
    replies.expire(until);
    assert!(
        replies
            .replay((1, 0, [9; 32], [7; 32]), &request.command, None)
            .map_err(|e| e.code.to_string())?
            .is_none()
    );
    Ok(())
}
