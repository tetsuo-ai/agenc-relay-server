//! An ERESUME naming an ordinary row past the committed acknowledgement is
//! that row's lost EACK (companion 12.5): its cumulative acknowledgement
//! commits before ERESUME OK, which then resumes after it. Any other cursor
//! stays fatal.
#![forbid(unsafe_code)]

use super::*;

/// The event identity of the retained row at `sequence`.
fn event_id(fixture: &Fixture, sequence: u64) -> TestResult<[u8; 16]> {
    fixture
        .coordinator
        .companion_exec
        .as_ref()
        .ok_or("executor")?
        .state
        .streams
        .get(&PEER)
        .ok_or("stream")?
        .rows
        .iter()
        .find(|row| row.sequence == sequence)
        .map(|row| row.event_id)
        .ok_or_else(|| "row".into())
}

fn live(fixture: &mut Fixture) -> TestResult<crate::federation::link::LinkQueue> {
    live_on(fixture, 1)
}

fn live_on(fixture: &mut Fixture, link: u64) -> TestResult<crate::federation::link::LinkQueue> {
    let (handle, queue) = link_queue(1 << 20);
    fixture.coordinator.peers.get_mut(&PEER).ok_or("peer")?.live = Some(LiveLink {
        link: LinkId::new(link),
        handle,
        incarnation: INCARNATION,
    });
    Ok(queue)
}

fn resume(fixture: &mut Fixture, generation: u64, last: (u64, [u8; 16])) -> Result<(), String> {
    resume_on(fixture, 1, generation, last)
}

fn resume_on(
    fixture: &mut Fixture,
    link: u64,
    generation: u64,
    last: (u64, [u8; 16]),
) -> Result<(), String> {
    let context = fixture.core.context_mut().map_err(|e| e.to_string())?;
    companion::admitted(
        &mut fixture.coordinator,
        context,
        LinkId::new(link),
        PEER,
        CompanionFrame::Resume {
            coordinator_server_id: *COORDINATOR.as_bytes(),
            server_incarnation: *INCARNATION.as_bytes(),
            delivery_generation: generation,
            last: Some(last),
        },
    )
    .map_err(|violation| format!("{violation:?}"))
}

/// Every line sent so far.
async fn sent(queue: &mut crate::federation::link::LinkQueue) -> Vec<String> {
    let mut lines = Vec::new();
    while let Ok(Some(line)) =
        tokio::time::timeout(std::time::Duration::from_millis(50), queue.recv()).await
    {
        lines.push(line.as_str().trim_end().to_owned());
    }
    lines
}

/// The delivery sequence of each retransmitted event, once per event.
fn event_sequences(lines: &[String]) -> Vec<u64> {
    let mut sequences: Vec<u64> = lines
        .iter()
        .filter_map(|line| {
            let mut words = line.split(' ').skip_while(|word| *word != "EEVENT");
            words.nth(3).and_then(|word| word.parse().ok())
        })
        .collect();
    sequences.dedup();
    sequences
}

#[tokio::test]
async fn a_resume_naming_a_lost_ordinary_ack_commits_it_before_resume_ok() -> TestResult {
    for named in [0, 1] {
        let mut fixture = Box::pin(Fixture::seed(true)).await?;
        let gate = fixture.stored_gate().await?.ok_or("gate")?;
        let mut queue = live(&mut fixture)?;
        let named_id = event_id(&fixture, named)?;
        resume(&mut fixture, 0, (named, named_id))?;
        assert_eq!(fixture.core.context_mut()?.pending_len(), 1, "{named}");
        assert!(sent(&mut queue).await.is_empty(), "nothing before commit");
        fixture.core.commit_staged_batch().await?;
        assert!(sent(&mut queue).await.is_empty(), "nothing before receipt");
        fixture
            .coordinator
            .batch_applied(fixture.core.context_mut()?);
        let lines = sent(&mut queue).await;
        let first = lines.first().ok_or("ERESUME OK")?;
        assert!(
            first.contains(" ERESUME OK ") && first.ends_with(&format!(" 0 {}", named + 1)),
            "{first}"
        );
        // Every later row is retransmitted, the barrier's parts included.
        assert_eq!(
            event_sequences(&lines),
            (named + 1..4).collect::<Vec<_>>(),
            "{lines:?}"
        );
        assert!(
            fixture
                .coordinator
                .companion_executor()
                .ok_or("executor")?
                .delivering(PEER)
        );
        // The barrier is still open: neither profile acknowledged it.
        assert_eq!(fixture.stored_gate().await?, Some(gate.clone()));
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
        assert_eq!(stream.acked, Some((named, named_id)));
        assert!(
            stream
                .rows
                .iter()
                .all(|row| row.acked() == (row.sequence <= named))
        );
        assert_eq!(fixture.coordinator.barriers.get(&PEER), Some(&gate));
    }
    Ok(())
}

#[tokio::test]
async fn a_resume_naming_no_retained_delivered_row_stays_fatal() -> TestResult {
    for defect in 0..3 {
        let mut fixture = Box::pin(Fixture::seed(true)).await?;
        let mut queue = live(&mut fixture)?;
        let cursor = match defect {
            // The second row under the first row's event ID.
            0 => (1, event_id(&fixture, 0)?),
            // A row past every row this stream delivered.
            1 => (4, [99; 16]),
            // An ordinary row under an unknown event ID.
            2 => (0, [99; 16]),
            _ => return Err("defect case".into()),
        };
        assert!(resume(&mut fixture, 0, cursor).is_err(), "defect {defect}");
        assert_eq!(fixture.core.context_mut()?.pending_len(), 0);
        assert!(sent(&mut queue).await.is_empty(), "defect {defect}");
        fixture.restart().await?;
        let stream = fixture
            .coordinator
            .companion_exec
            .as_ref()
            .ok_or("executor")?
            .state
            .streams
            .get(&PEER)
            .ok_or("stream")?;
        assert_eq!(stream.acked, None, "defect {defect}");
    }
    Ok(())
}

#[tokio::test]
async fn a_resume_acknowledgement_storage_refused_retires_its_link() -> TestResult {
    let mut fixture = Box::pin(Fixture::seed(true)).await?;
    let mut first = live(&mut fixture)?;
    let named_id = event_id(&fixture, 1)?;
    resume(&mut fixture, 0, (1, named_id))?;
    assert_eq!(fixture.core.context_mut()?.pending_len(), 1);
    fixture
        .core
        .state_mut()?
        .reject_fixture_batch_before_submission(agenc_relay_storage::StorageError::QueueFull)?;
    fixture
        .coordinator
        .batch_rejected(fixture.core.context_mut()?);
    // The acknowledgement did not persist: its link is retired, nothing is
    // recorded, and no ERESUME OK goes out.
    assert!(!fixture.coordinator.link_is_live(LinkId::new(1), PEER));
    assert!(sent(&mut first).await.is_empty());
    assert_eq!(fixture.core.context_mut()?.pending_len(), 0);
    let stream = fixture
        .coordinator
        .companion_exec
        .as_ref()
        .ok_or("executor")?
        .state
        .streams
        .get(&PEER)
        .ok_or("stream")?;
    assert_eq!(stream.acked, None);
    // The edge resumes from the same durable cursor on its next link, which
    // commits it and answers ERESUME OK.
    let mut second = live_on(&mut fixture, 2)?;
    resume_on(&mut fixture, 2, 0, (1, named_id))?;
    fixture.core.commit_staged_batch().await?;
    fixture
        .coordinator
        .batch_applied(fixture.core.context_mut()?);
    let lines = sent(&mut second).await;
    let ok = lines.first().ok_or("ERESUME OK")?;
    assert!(ok.contains(" ERESUME OK ") && ok.ends_with(" 0 2"), "{ok}");
    assert_eq!(event_sequences(&lines), vec![2, 3], "{lines:?}");
    assert!(fixture.coordinator.link_is_live(LinkId::new(2), PEER));
    fixture.restart().await?;
    let stream = fixture
        .coordinator
        .companion_exec
        .as_ref()
        .ok_or("executor")?
        .state
        .streams
        .get(&PEER)
        .ok_or("stream")?;
    assert_eq!(stream.acked, Some((1, named_id)));
    Ok(())
}

#[tokio::test]
async fn an_acknowledgement_storage_refused_retires_its_link() -> TestResult {
    let mut fixture = Box::pin(Fixture::seed(true)).await?;
    let mut queue = live(&mut fixture)?;
    // An exact resume before any acknowledgement activates the stream.
    let context = fixture.core.context_mut()?;
    companion::admitted(
        &mut fixture.coordinator,
        context,
        LinkId::new(1),
        PEER,
        CompanionFrame::Resume {
            coordinator_server_id: *COORDINATOR.as_bytes(),
            server_incarnation: *INCARNATION.as_bytes(),
            delivery_generation: 0,
            last: None,
        },
    )
    .map_err(|e| format!("resume: {e:?}"))?;
    assert!(
        sent(&mut queue)
            .await
            .first()
            .is_some_and(|line| line.contains(" ERESUME OK "))
    );
    let first = event_id(&fixture, 0)?;
    let context = fixture.core.context_mut()?;
    companion::admitted(
        &mut fixture.coordinator,
        context,
        LinkId::new(1),
        PEER,
        CompanionFrame::Ack(agenc_relay_e2ee::federation::frames::DeliveryPosition {
            server_id: *COORDINATOR.as_bytes(),
            delivery_generation: 0,
            delivery_sequence: 0,
            event_id: first,
        }),
    )
    .map_err(|e| format!("ack: {e:?}"))?;
    assert_eq!(fixture.core.context_mut()?.pending_len(), 1);
    fixture
        .core
        .state_mut()?
        .reject_fixture_batch_before_submission(agenc_relay_storage::StorageError::QueueFull)?;
    fixture
        .coordinator
        .batch_rejected(fixture.core.context_mut()?);
    // The edge counts the event as acknowledged; its link is retired, and
    // its next ERESUME names that cursor again.
    assert!(!fixture.coordinator.link_is_live(LinkId::new(1), PEER));
    let stream = fixture
        .coordinator
        .companion_exec
        .as_ref()
        .ok_or("executor")?
        .state
        .streams
        .get(&PEER)
        .ok_or("stream")?;
    assert_eq!(stream.acked, None);
    Ok(())
}
