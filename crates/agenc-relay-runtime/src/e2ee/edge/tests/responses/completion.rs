#![forbid(unsafe_code)]

//! Authenticated result, response object and durable completion in every arrival order.

use super::*;
use agenc_relay_e2ee::federation::frames::DeliveryPosition;
use agenc_relay_e2ee::objects::federation::ArcFederationEvent;

/// Feed the actual EVENT envelope through the normal assembly and durable
/// cursor owner. No client reply is visible while the write is staged.
pub(super) fn stage(
    edge: &mut E2eeEdge,
    fixture: &mut StateCoreFixture,
    base: &mut EdgeFederation,
    event: &ArcFederationEvent,
) -> TestResult {
    edge.phase = Phase::Active;
    edge.witness_snapshot_required = false;
    edge.delivery.generation = event.delivery_generation;
    edge.delivery.cursor = event
        .delivery_sequence
        .checked_sub(1)
        .map(|n| (n, [92; 16]));
    let position = DeliveryPosition {
        server_id: event.target_server_id,
        delivery_generation: event.delivery_generation,
        delivery_sequence: event.delivery_sequence,
        event_id: event.event_id,
    };
    let bytes =
        ArcWireObject::new(ArcWireObjectKind::FederationEvent, event.encode()?)?.encode()?;
    let id = *ObjectId::compute(&bytes).as_bytes();
    for fragment in fragment_object(&bytes)? {
        let outputs = edge
            .on_event_frame(fixture.context_mut()?, base, position, id, fragment, false)
            .map_err(|e| e.code.to_string())?;
        assert!(outputs.is_empty(), "early event output");
    }
    assert!(
        fixture.context_mut()?.pending_len() > 0,
        "real cursor write staged"
    );
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum Step {
    Result,
    Data,
    Stage,
    Commit,
}

#[tokio::test]
async fn a_labeled_batch_waits_for_its_own_result_object_and_durable_completion_in_any_order()
-> TestResult {
    use Step::*;
    // Above one fragment but below the unsolicited-live limit: all six
    // delivery orders are legal. Commit is independent of staging.
    let orders = [
        [Result, Data, Stage, Commit],
        [Data, Result, Stage, Commit],
        [Result, Stage, Data, Commit],
        [Data, Stage, Result, Commit],
        [Stage, Data, Result, Commit],
        [Stage, Result, Data, Commit],
        [Stage, Commit, Data, Result],
        [Stage, Commit, Result, Data],
        [Result, Stage, Commit, Data],
        [Data, Stage, Commit, Result],
        [Stage, Data, Commit, Result],
        [Stage, Result, Commit, Data],
    ];
    let bytes = object(ArcWireObjectKind::WelcomeMls, 5021, 41)?;
    let event = super::super::result_kinds::completion_event()?;
    let result = result_with_completion(vec![descriptor(0, &bytes)?], 1, Some(event.event_id))?;
    for order in orders {
        let mut fixture = StateCoreFixture::new(vec![0; 4096])?;
        let mut edge = waiting();
        let mut base = super::super::projection::base_edge();
        let mut emitted = 0;
        let mut committed = false;
        for (index, action) in order.into_iter().enumerate() {
            let outputs = match action {
                Result => receive(&mut edge, &mut fixture, None, &result)?,
                Data => receive(&mut edge, &mut fixture, Some(0), &bytes)?,
                Stage => {
                    stage(&mut edge, &mut fixture, &mut base, &event)?;
                    Vec::new()
                }
                Commit => {
                    fixture.commit_staged_batch().await?;
                    committed = true;
                    edge.batch_applied(fixture.context_mut()?, &mut base)
                }
            };
            if index < 3 {
                assert!(outputs.is_empty(), "{order:?}");
            }
            for output in outputs {
                assert!(committed);
                assert!(output.frames.is_empty());
                let mut batch = output.batch.ok_or("expected a streamed batch")?;
                let opener = batch
                    .next_line()
                    .map_err(|e| e.to_string())?
                    .ok_or("batch opener")?;
                assert!(std::str::from_utf8(opener.as_bytes())?.starts_with("@label=fetch "));
                emitted += 1;
            }
        }
        assert_eq!(emitted, 1, "{order:?}");
        assert!(!edge.pending.contains_key(&REQUEST));
        assert_eq!(edge.counters.results_rendered, 1);
    }
    Ok(())
}

#[tokio::test]
async fn rejecting_the_cursor_or_disconnecting_the_recipient_never_publishes_its_prepared_stream()
-> TestResult {
    let bytes = object(ArcWireObjectKind::WelcomeMls, 9011, 31)?;
    let event = super::super::result_kinds::completion_event()?;
    let result = result_with_completion(vec![descriptor(0, &bytes)?], 1, Some(event.event_id))?;
    for disconnect in [true, false] {
        let mut edge = waiting();
        let mut base = super::super::projection::base_edge();
        let mut fixture = StateCoreFixture::new(vec![0; 4096])?;
        assert!(receive(&mut edge, &mut fixture, None, &result)?.is_empty());
        assert!(receive(&mut edge, &mut fixture, Some(0), &bytes)?.is_empty());
        stage(&mut edge, &mut fixture, &mut base, &event)?;
        if disconnect {
            edge.connection_closed(ConnectionGeneration::new(1));
            fixture.commit_staged_batch().await?;
            assert!(
                edge.batch_applied(fixture.context_mut()?, &mut base)
                    .is_empty()
            );
            assert!(!edge.pending.contains_key(&REQUEST));
        } else {
            edge.batch_rejected(fixture.context_mut()?, &mut base);
            let pending = edge
                .pending
                .get(&REQUEST)
                .ok_or("rollback lost retryable request")?;
            assert!(!pending.completion_seen);
            assert_eq!(
                pending.responses.get(&0).map(AsRef::as_ref),
                Some(bytes.as_slice())
            );
            assert!(
                edge.render_ready(fixture.context_mut()?, REQUEST)
                    .map_err(|e| e.code.to_string())?
                    .is_empty()
            );
        }
        assert_eq!(edge.counters.results_rendered, 0);
    }
    Ok(())
}
