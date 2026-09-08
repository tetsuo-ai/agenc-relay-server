//! Refused or obsolete cleanup jobs cannot change durable replay authority.
#![forbid(unsafe_code)]

use super::*;

#[tokio::test]
async fn rejected_cleanup_and_a_crash_before_its_receipt_resume_from_the_durable_prefix()
-> TestResult {
    let mut fixture = Box::pin(logically_expired()).await?;
    let before = stream(&fixture)?.acked;
    retry(&mut fixture)?;
    reads(&mut fixture).await?;
    fixture
        .core
        .state_mut()?
        .reject_fixture_batch_before_submission(agenc_ircd_storage::StorageError::QueueFull)?;
    fixture
        .coordinator
        .batch_rejected(fixture.core.context_mut()?);
    assert_eq!(physical_rows(&mut fixture, false).await?, 2);
    fixture.restart().await?;
    assert!(fixture.coordinator.loaded());
    wake(&mut fixture)?;
    assert_eq!(reads(&mut fixture).await?, 2);
    fixture.core.commit_staged_batch().await?;
    // Deliberately lose the publication callback after durable deletion.
    fixture.restart().await?;
    assert!(fixture.coordinator.loaded());
    assert_eq!(physical_rows(&mut fixture, false).await?, 0);
    assert_eq!(physical_rows(&mut fixture, true).await?, 1);
    wake(&mut fixture)?;
    assert_eq!(reads(&mut fixture).await?, 3);
    fixture.core.commit_staged_batch().await?;
    fixture
        .coordinator
        .batch_applied(fixture.core.context_mut()?);
    assert_eq!(physical_rows(&mut fixture, true).await?, 0);
    assert_eq!(stream(&fixture)?.acked, before);
    Ok(())
}

#[tokio::test]
async fn changed_base_scope_keeps_the_cleanup_read_owned_until_its_completion() -> TestResult {
    let mut fixture = Box::pin(logically_expired()).await?;
    retry(&mut fixture)?;
    let message = fixture.core.next_storage_read().await?;
    let id = message.read_id;
    fixture
        .coordinator
        .peers
        .get_mut(&PEER)
        .ok_or("peer")?
        .client_resync_epoch = 1;
    assert!(fixture.coordinator.owns_storage_read(id));
    fixture
        .coordinator
        .storage_read_completed(fixture.core.context_mut()?, message);
    assert!(!fixture.coordinator.owns_storage_read(id));
    assert!(fixture.coordinator.pending.is_none());
    assert_eq!(physical_rows(&mut fixture, false).await?, 2);
    fixture.restart().await?;
    assert!(fixture.coordinator.loaded());
    Ok(())
}

#[tokio::test]
async fn cleanup_uses_the_committed_floor_even_when_the_current_wall_clock_is_unavailable()
-> TestResult {
    let mut fixture = Box::pin(logically_expired()).await?;
    fixture
        .core
        .context_mut()?
        .set_untrusted_wall_for_test(None);
    retry(&mut fixture)?;
    assert_eq!(reads(&mut fixture).await?, 2);
    fixture.core.commit_staged_batch().await?;
    fixture
        .coordinator
        .batch_applied(fixture.core.context_mut()?);
    assert_eq!(physical_rows(&mut fixture, false).await?, 0);
    Ok(())
}

#[tokio::test]
async fn cleanup_refuses_an_unrelated_commit_between_its_owner_and_prefix_pages() -> TestResult {
    let mut fixture = Box::pin(logically_expired()).await?;
    retry(&mut fixture)?;
    let message = fixture.core.next_storage_read().await?;
    let write = fixture.coordinator.peer_row_at(PEER, 1, None)?;
    Box::pin(fixture.commit(vec![write])).await?;
    fixture
        .coordinator
        .storage_read_completed(fixture.core.context_mut()?, message);
    assert_eq!(reads(&mut fixture).await?, 1);
    assert!(fixture.coordinator.pending.is_none());
    assert!(fixture.coordinator.loaded());
    assert_eq!(physical_rows(&mut fixture, false).await?, 2);
    Ok(())
}
