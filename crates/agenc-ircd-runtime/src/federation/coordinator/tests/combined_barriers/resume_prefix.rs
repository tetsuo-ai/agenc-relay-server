//! A final barrier resume includes the complete retained ordinary prefix.
#![forbid(unsafe_code)]

use super::*;

#[tokio::test]
async fn final_barrier_resume_recovers_lost_ordinary_prefix_acks_after_base_commit() -> TestResult {
    let mut fixture = Box::pin(Fixture::seed(true)).await?;
    assert_eq!(fixture.gate.companion().first(), 2);
    assert_eq!(fixture.gate.companion().last(), 3);
    fixture.stage_base_ack()?;
    fixture.core.commit_staged_batch().await?;
    fixture
        .coordinator
        .batch_applied(fixture.core.context_mut()?);
    fixture.restart().await?;
    assert!(fixture.coordinator.loaded());
    let before = fixture.stored_gate().await?.ok_or("remaining gate")?;
    assert!(before.base_acked());
    assert!(!before.companion_acked());
    let stream = fixture
        .coordinator
        .companion_exec
        .as_ref()
        .ok_or("executor")?
        .state
        .streams
        .get(&PEER)
        .ok_or("stream")?;
    assert!(stream.acked.is_none());
    assert_eq!(stream.rows.len(), 4);
    let (handle, mut queue) = link_queue(1 << 20);
    fixture.coordinator.peers.get_mut(&PEER).ok_or("peer")?.live = Some(LiveLink {
        link: LinkId::new(1),
        handle,
        incarnation: INCARNATION,
    });
    companion::admitted(
        &mut fixture.coordinator,
        fixture.core.context_mut()?,
        LinkId::new(1),
        PEER,
        CompanionFrame::Resume {
            coordinator_server_id: *COORDINATOR.as_bytes(),
            server_incarnation: *INCARNATION.as_bytes(),
            delivery_generation: 0,
            last: Some((
                before.companion().last(),
                before.companion().final_event_id(),
            )),
        },
    )
    .map_err(|e| format!("final resume with ordinary prefix: {e:?}"))?;
    assert_eq!(fixture.stored_gate().await?, Some(before.clone()));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(10), queue.recv())
            .await
            .is_err()
    );
    fixture.core.commit_staged_batch().await?;
    assert_eq!(fixture.coordinator.barriers.get(&PEER), Some(&before));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(10), queue.recv())
            .await
            .is_err()
    );
    fixture
        .coordinator
        .batch_applied(fixture.core.context_mut()?);
    let line = tokio::time::timeout(std::time::Duration::from_secs(2), queue.recv())
        .await?
        .ok_or("resume reply")?;
    assert!(line.as_str().contains(" ERESUME OK "), "{}", line.as_str());
    assert!(fixture.stored_gate().await?.is_none());
    fixture.restart().await?;
    assert!(fixture.coordinator.loaded());
    assert!(!fixture.coordinator.barriers.contains_key(&PEER));
    let stream = fixture
        .coordinator
        .companion_exec
        .as_ref()
        .ok_or("executor")?
        .state
        .streams
        .get(&PEER)
        .ok_or("stream")?;
    assert_eq!(stream.acked, Some((3, before.companion().final_event_id())));
    assert_eq!(stream.next_sequence, 4);
    assert!(stream.rows.iter().all(|row| row.acked()));
    Ok(())
}

#[tokio::test]
async fn ordinary_eack_cannot_skip_the_unacknowledged_prefix() -> TestResult {
    let mut fixture = Box::pin(Fixture::seed(true)).await?;
    assert!(fixture.stage_companion_ack().is_err());
    assert_eq!(fixture.core.context_mut()?.pending_len(), 0);
    assert_eq!(fixture.stored_gate().await?, Some(fixture.gate.clone()));
    fixture.restart().await?;
    assert!(fixture.coordinator.loaded());
    let stream = fixture
        .coordinator
        .companion_exec
        .as_ref()
        .ok_or("executor")?
        .state
        .streams
        .get(&PEER)
        .ok_or("stream")?;
    assert!(stream.acked.is_none());
    Ok(())
}

#[tokio::test]
async fn incomplete_or_mismatched_barrier_resumes_cannot_stage_coverage() -> TestResult {
    for defect in 0..4 {
        let mut fixture = Box::pin(Fixture::seed(true)).await?;
        let (handle, mut queue) = link_queue(1 << 20);
        fixture.coordinator.peers.get_mut(&PEER).ok_or("peer")?.live = Some(LiveLink {
            link: LinkId::new(1),
            handle,
            incarnation: INCARNATION,
        });
        let stream = fixture
            .coordinator
            .companion_exec
            .as_mut()
            .ok_or("executor")?
            .state
            .streams
            .get_mut(&PEER)
            .ok_or("stream")?;
        let mut sequence = fixture.gate.companion().last();
        let mut event_id = fixture.gate.companion().final_event_id();
        let mut generation = 0;
        match defect {
            // An inconsistent in-memory prefix must fail before any durable write.
            0 => {
                stream.rows.remove(1).ok_or("ordinary row")?;
            }
            1 => {
                let partial = stream
                    .rows
                    .iter()
                    .find(|row| row.sequence == 2)
                    .ok_or("part")?;
                sequence = partial.sequence;
                event_id = partial.event_id;
            }
            2 => event_id = [99; 16],
            3 => generation = 1,
            _ => return Err("defect case".into()),
        }
        assert!(
            companion::admitted(
                &mut fixture.coordinator,
                fixture.core.context_mut()?,
                LinkId::new(1),
                PEER,
                CompanionFrame::Resume {
                    coordinator_server_id: *COORDINATOR.as_bytes(),
                    server_incarnation: *INCARNATION.as_bytes(),
                    delivery_generation: generation,
                    last: Some((sequence, event_id)),
                },
            )
            .is_err(),
            "defect {defect}"
        );
        assert_eq!(fixture.core.context_mut()?.pending_len(), 0);
        assert_eq!(fixture.stored_gate().await?, Some(fixture.gate.clone()));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), queue.recv())
                .await
                .is_err()
        );
        fixture.restart().await?;
        assert!(fixture.coordinator.loaded());
        let stream = fixture
            .coordinator
            .companion_exec
            .as_ref()
            .ok_or("executor")?
            .state
            .streams
            .get(&PEER)
            .ok_or("stream")?;
        assert!(stream.acked.is_none());
    }
    Ok(())
}
