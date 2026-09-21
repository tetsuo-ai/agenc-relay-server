//! Actual sealed FETCH commits preserve offered-page ownership and original bytes.
#![forbid(unsafe_code)]

mod refusal;

use super::*;

fn fetch_frame(fixture: &RestartFixture, page: u32) -> TestResult<CompanionFrame> {
    let snapshot = fixture
        .coordinator
        .peer_sync(home())
        .and_then(|sync| sync.snapshot.as_ref())
        .ok_or("Pending cut")?;
    let cursor = snapshot
        .capture
        .cursor(page.checked_sub(1).ok_or("page zero FETCH")? as usize)
        .ok_or("original random cursor")?;
    Ok(CompanionFrame::StateFetch {
        coordinator_server_id: *fixture.storage.identity.server_id.as_bytes(),
        snapshot_token: snapshot.cut.token,
        next_page_sequence: page,
        cursor,
    })
}

fn expected_page(fixture: &RestartFixture, page: usize) -> TestResult<Vec<CompanionFrame>> {
    let snapshot = fixture
        .coordinator
        .peer_sync(home())
        .and_then(|sync| sync.snapshot.as_ref())
        .ok_or("Pending cut")?;
    let lines = crate::e2ee::coordinator::sync::render_page(
        SERVER_NAME,
        home(),
        snapshot,
        page,
        &fixture.coordinator.state,
    )?;
    lines.iter().map(parse).collect()
}

async fn complete_read(
    fixture: &mut RestartFixture,
    actions: Vec<Action>,
) -> TestResult<Vec<Action>> {
    let Some(Action::ReadSnapshotPage(request)) = actions.into_iter().next() else {
        return Err("Stored page must request an exact bounded read".into());
    };
    let key = request.key()?;
    let (_, value) = read_value(fixture, TableId::E2eeState, &key).await?;
    Ok(request.complete(
        &mut fixture.coordinator,
        &key,
        &value,
        NOW_MILLIS,
        &fixture.host,
    )?)
}

#[tokio::test]
async fn fetch_advance_is_silent_until_storage_and_exact_retry_needs_no_second_write() -> TestResult
{
    let mut fixture = pending_fixture(65).await?;
    let before = owner(&fixture)?;
    let expected = expected_page(&fixture, 1)?;
    let frame = fetch_frame(&fixture, 1)?;
    let actions = fixture.frame(frame.clone())?;
    assert!(frames(&actions)?.is_empty());
    assert_eq!(owner(&fixture)?, before);
    let Some(Action::Stage {
        writes,
        work: PendingWork::Fetch(publication),
    }) = actions.into_iter().next()
    else {
        return Err("FETCH must stage exactly its offered-page owner before sending".into());
    };
    fixture
        .coordinator
        .set_pending(PendingWork::Fetch(publication));
    fixture.commit(writes).await?;
    let Some(Committed::Fetch(publication)) = fixture.coordinator.batch_applied(Some(0))? else {
        return Err("exact FETCH receipt".into());
    };
    let actions = publication.committed(&mut fixture.coordinator, NOW_MILLIS, &fixture.host)?;
    assert_eq!(frames(&actions)?, expected);
    let after = owner(&fixture)?;
    assert!(matches!(
        after.phase(),
        CutPhase::Pending {
            offered_pages: 2,
            ..
        }
    ));
    assert_eq!(before.cut(), after.cut());
    assert_eq!(before.cursor(), after.cursor());
    let retry = fixture.frame(frame)?;
    assert!(matches!(retry.as_slice(), [Action::SendPage(_)]));
    assert_eq!(frames(&retry)?, expected);
    assert_eq!(owner(&fixture)?, after);
    Ok(())
}

#[tokio::test]
async fn crash_after_fetch_commit_before_output_replays_the_same_immutable_page() -> TestResult {
    let mut fixture = pending_fixture(65).await?;
    let expected = expected_page(&fixture, 1)?;
    let frame = fetch_frame(&fixture, 1)?;
    let actions = fixture.frame(frame.clone())?;
    let Some(Action::Stage { writes, work }) = actions.into_iter().next() else {
        return Err("FETCH stage".into());
    };
    // Commit the actual Owner Put, then lose all volatile completion state.
    fixture.commit(writes).await?;
    drop(work);
    fixture.coordinator = reconstruct(&mut fixture).await?;
    fixture.host.clock = crate::e2ee::coordinator::delivery_owner::clock::sample();
    let durable = owner(&fixture)?;
    assert!(matches!(
        durable.phase(),
        CutPhase::Pending {
            offered_pages: 2,
            ..
        }
    ));
    let read = fixture.frame(frame)?;
    assert!(frames(&read)?.is_empty());
    let replay = complete_read(&mut fixture, read).await?;
    assert!(matches!(replay.as_slice(), [Action::SendPage(_)]));
    assert_eq!(frames(&replay)?, expected);
    assert_eq!(owner(&fixture)?, durable);
    Ok(())
}

#[tokio::test]
async fn restored_pending_fetch_reads_sealed_page_then_stages_its_offered_boundary() -> TestResult {
    let mut fixture = pending_fixture(65).await?;
    let expected = expected_page(&fixture, 1)?;
    let frame = fetch_frame(&fixture, 1)?;
    let initial = owner(&fixture)?;
    fixture.coordinator = reconstruct(&mut fixture).await?;
    fixture.host.clock = crate::e2ee::coordinator::delivery_owner::clock::sample();
    let read = fixture.frame(frame)?;
    let actions = complete_read(&mut fixture, read).await?;
    assert!(frames(&actions)?.is_empty());
    assert_eq!(owner(&fixture)?, initial);
    let Some(Action::Stage { writes, work }) = actions.into_iter().next() else {
        return Err("Stored FETCH must stage its exact Owner boundary".into());
    };
    fixture.coordinator.set_pending(work);
    fixture.commit(writes).await?;
    let Some(Committed::Fetch(publication)) = fixture.coordinator.batch_applied(Some(0))? else {
        return Err("Stored FETCH receipt".into());
    };
    let published = publication.committed(&mut fixture.coordinator, NOW_MILLIS, &fixture.host)?;
    assert_eq!(frames(&published)?, expected);
    Ok(())
}
