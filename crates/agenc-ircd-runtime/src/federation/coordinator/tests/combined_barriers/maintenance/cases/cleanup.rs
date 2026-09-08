//! Physical metadata cleanup follows an already committed retention floor.
#![forbid(unsafe_code)]

use super::*;
use agenc_ircd_storage::e2ee_records::delivery_recovery::{outbox, outbox::replay};

mod admission;
mod bounded;
mod failures;

async fn physical_rows(fixture: &mut Fixture, ranges: bool) -> TestResult<usize> {
    let plan = if ranges {
        replay::ack_ranges_from(fixture.gate.scope(), 0, 0, 128)?
    } else {
        outbox::outbox_from(fixture.gate.scope(), 0, 0, 128)?
    };
    let id = fixture.core.context_mut()?.submit_storage_read(plan)?;
    let message = fixture.core.next_storage_read().await?;
    assert_eq!(id, message.read_id);
    let result = message.result?;
    assert!(!result.truncated);
    Ok(result.records.len())
}

async fn logically_expired() -> TestResult<Fixture> {
    let mut fixture = Box::pin(expired(true, true)).await?;
    wake(&mut fixture)?;
    reads(&mut fixture).await?;
    fixture.core.commit_staged_batch().await?;
    fixture
        .coordinator
        .batch_applied(fixture.core.context_mut()?);
    assert!(stream(&fixture)?.rows.is_empty());
    assert_eq!(physical_rows(&mut fixture, false).await?, 2);
    assert_eq!(physical_rows(&mut fixture, true).await?, 1);
    Ok(fixture)
}

fn retry(fixture: &mut Fixture) -> TestResult {
    let now = fixture.core.context_mut()?.now().get();
    fixture
        .core
        .context_mut()?
        .set_monotonic_for_test(now.checked_add(1_000).ok_or("tick")?);
    wake(fixture)
}

#[tokio::test]
async fn timer_deletes_obsolete_outbox_and_ack_ranges_after_the_durable_floor() -> TestResult {
    let mut fixture = Box::pin(logically_expired()).await?;
    let before = stream(&fixture)?.acked;
    retry(&mut fixture)?;
    assert!(
        fixture.coordinator.replay_maintenance.busy(),
        "the committed replay floor did not schedule physical metadata cleanup"
    );
    assert_eq!(reads(&mut fixture).await?, 2);
    assert_eq!(physical_rows(&mut fixture, false).await?, 2);
    fixture.core.commit_staged_batch().await?;
    fixture
        .coordinator
        .batch_applied(fixture.core.context_mut()?);
    assert_eq!(physical_rows(&mut fixture, false).await?, 0);
    assert_eq!(physical_rows(&mut fixture, true).await?, 1);
    retry(&mut fixture)?;
    assert_eq!(reads(&mut fixture).await?, 3);
    fixture.core.commit_staged_batch().await?;
    fixture
        .coordinator
        .batch_applied(fixture.core.context_mut()?);
    assert_eq!(physical_rows(&mut fixture, true).await?, 0);
    retry(&mut fixture)?;
    assert_eq!(reads(&mut fixture).await?, 3);
    assert!(fixture.coordinator.pending.is_none());
    assert_eq!(stream(&fixture)?.acked, before);
    fixture.restart().await?;
    assert!(fixture.coordinator.loaded());
    assert!(stream(&fixture)?.rows.is_empty());
    assert_eq!(stream(&fixture)?.acked, before);
    Ok(())
}
