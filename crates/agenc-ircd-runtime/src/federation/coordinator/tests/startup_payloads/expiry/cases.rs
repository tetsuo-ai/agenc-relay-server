//! Expiry preserves exact receipt, clock, capacity and restart boundaries.
#![forbid(unsafe_code)]
use super::*;
use crate::state_core::timers::TimerHeap;
use agenc_ircd_domain::e2ee::mailbox::{AckOutcome, MailboxError, Target};
use fixture::{Fixture, item_key, stored, token};

const TARGET: Target = Target {
    account_digest: [1; 32],
    device_id: [2; 16],
};

#[tokio::test]
async fn expired_grants_and_acks_are_removed_without_deleting_a_live_shared_item() -> TestResult {
    let mut f = Fixture::new(1, true, true).await?;
    f.wake()?;
    f.commit().await?;
    assert_eq!(f.executor()?.state.mailboxes.item_count(), 1);
    assert!(f.executor()?.state.objects.contains_key(&f.id));
    assert!(
        stored(&mut f.core, TableId::E2eeState, item_key(0)?)
            .await?
            .is_none()
    );
    let row = stored(&mut f.core, TableId::E2eeState, item_key(1)?)
        .await?
        .ok_or("live item")?;
    assert!(matches!(
        MailboxRow::decode(row.body())?,
        MailboxRow::Item {
            expires_at: 4000,
            grant: None,
            ..
        }
    ));
    assert_eq!(
        row.revision(),
        f.core.context_mut()?.domain().revision().get()
    );
    for sequence in 0..2 {
        assert!(
            stored(
                &mut f.core,
                TableId::E2eeState,
                MailboxRow::token_key(&token(sequence))?
            )
            .await?
            .is_none()
        );
    }
    f.retry()?;
    f.commit().await?;
    assert!(
        stored(
            &mut f.core,
            TableId::E2eeState,
            MailboxRow::ack_key(&[1; 32], &[2; 16], &[250; 32])?
        )
        .await?
        .is_none()
    );
    assert!(
        stored(
            &mut f.core,
            TableId::E2eeState,
            MailboxRow::ack_key(&[1; 32], &[2; 16], &[251; 32])?
        )
        .await?
        .is_some()
    );
    f.restart().await?;
    let id = f.id;
    let executor = f.coordinator.companion_exec.as_mut().ok_or("executor")?;
    assert_eq!(
        executor
            .state
            .mailboxes
            .acknowledge(TARGET, [250; 32], id, 7, 2000),
        Err(MailboxError::TokenInvalid)
    );
    assert_eq!(
        executor
            .state
            .mailboxes
            .acknowledge(TARGET, [251; 32], id, 7, 2000),
        Ok(AckOutcome::Replayed)
    );
    assert_eq!(executor.state.mailboxes.item_count(), 1);
    assert!(executor.state.objects.contains_key(&id));
    Ok(())
}

#[tokio::test]
async fn a_rejected_page_keeps_items_and_backing_and_retries_the_same_position() -> TestResult {
    let mut f = Fixture::new(1, false, false).await?;
    let budget = f.core.context_mut()?.backing_budget_for_test();
    let baseline = budget.charged();
    f.wake()?;
    assert!(budget.charged() > baseline);
    f.core
        .state_mut()?
        .reject_fixture_batch_before_submission(agenc_ircd_storage::StorageError::QueueFull)?;
    f.coordinator.batch_rejected(f.core.context_mut()?);
    assert!(f.coordinator.pending.is_none());
    assert_eq!(f.executor()?.state.mailboxes.item_count(), 1);
    assert_eq!(budget.charged(), baseline);
    assert!(
        stored(&mut f.core, TableId::E2eeState, item_key(0)?)
            .await?
            .is_some()
    );
    f.retry()?;
    f.commit().await?;
    assert_eq!(f.executor()?.state.mailboxes.item_count(), 0);
    assert!(budget.charged() < baseline);
    Ok(())
}

#[tokio::test]
async fn a_partial_page_receipt_lost_before_publication_recovers_remaining_items() -> TestResult {
    let mut f = Fixture::new(130, false, false).await?;
    f.wake()?;
    f.core.commit_staged_batch().await?;
    assert_eq!(f.executor()?.state.mailboxes.item_count(), 130);
    f.restart().await?;
    assert_eq!(f.executor()?.state.mailboxes.item_count(), 2);
    assert!(f.executor()?.state.objects.contains_key(&f.id));
    assert!(
        stored(&mut f.core, TableId::E2eeState, item_key(127)?)
            .await?
            .is_none()
    );
    assert!(
        stored(&mut f.core, TableId::E2eeState, item_key(128)?)
            .await?
            .is_some()
    );
    f.wake()?;
    f.commit().await?;
    assert_eq!(f.executor()?.state.mailboxes.item_count(), 0);
    assert!(!f.executor()?.state.objects.contains_key(&f.id));
    f.restart().await?;
    let executor = f.coordinator.companion_exec.as_mut().ok_or("executor")?;
    assert_eq!(
        executor.state.mailboxes.deliver(
            TARGET,
            agenc_ircd_domain::e2ee::mailbox::MailboxKind::Application,
            f.id,
            [8; 32],
            2000,
            1000
        )?,
        130
    );
    Ok(())
}

#[tokio::test]
async fn unknown_or_regressed_wall_time_cannot_stage_expiry() -> TestResult {
    for wall in [None, Some(1998)] {
        let mut f = Fixture::new(1, false, false).await?;
        f.core.context_mut()?.set_untrusted_wall_for_test(wall);
        f.wake()?;
        assert!(f.coordinator.pending.is_none());
        assert_eq!(f.executor()?.state.mailboxes.item_count(), 1);
        f.core.context_mut()?.set_wall_for_test(2000);
        f.retry()?;
        f.commit().await?;
        assert_eq!(f.executor()?.state.mailboxes.item_count(), 0);
    }
    Ok(())
}

#[tokio::test]
async fn quiescing_preserves_mailboxes_and_a_later_clock_change_cannot_undo_a_receipt() -> TestResult
{
    let mut f = Fixture::new(1, false, false).await?;
    f.core.context_mut()?.quiesce_for_test();
    f.wake()?;
    assert!(f.coordinator.pending.is_none());
    assert_eq!(f.executor()?.state.mailboxes.item_count(), 1);
    let mut f = Fixture::new(1, false, false).await?;
    f.wake()?;
    f.core.context_mut()?.set_untrusted_wall_for_test(None);
    f.commit().await?;
    assert_eq!(f.executor()?.state.mailboxes.item_count(), 0);
    f.restart().await?;
    assert_eq!(f.executor()?.state.mailboxes.item_count(), 0);
    Ok(())
}

#[tokio::test]
async fn refused_memory_releases_private_plans_and_retries_after_capacity_returns() -> TestResult {
    for headroom in [8192, 128 * 512 + 16384] {
        let mut f = Fixture::new(1, false, false).await?;
        let budget = f.core.context_mut()?.backing_budget_for_test();
        let held = f
            .core
            .context_mut()?
            .reserve_output_backing(usize::try_from(budget.available())? - headroom)?;
        let charged = budget.charged();
        f.wake()?;
        assert!(f.coordinator.pending.is_none());
        assert_eq!(f.executor()?.state.mailboxes.item_count(), 1);
        assert_eq!(budget.charged(), charged);
        drop(held);
        f.retry()?;
        f.commit().await?;
        assert_eq!(f.executor()?.state.mailboxes.item_count(), 0);
    }
    Ok(())
}

#[tokio::test]
async fn timer_refusal_can_use_the_existing_retention_sweep_without_client_traffic() -> TestResult {
    let mut f = Fixture::new(1, false, false).await?;
    *f.core.context_mut()?.timers_mut() = TimerHeap::with_ceiling(0);
    super::super::super::super::mailbox_expiry::restored(&mut f.coordinator, f.core.context_mut()?);
    f.coordinator.continue_restore(f.core.context_mut()?);
    f.commit().await?;
    assert_eq!(f.executor()?.state.mailboxes.item_count(), 0);
    Ok(())
}

#[tokio::test]
async fn a_changed_captured_item_refuses_publication_after_storage_commits() -> TestResult {
    let mut f = Fixture::new(2, false, false).await?;
    f.wake()?;
    let executor = f.coordinator.companion_exec.as_mut().ok_or("executor")?;
    let kind = agenc_ircd_domain::e2ee::mailbox::MailboxKind::Application;
    let mut item = *executor
        .state
        .mailboxes
        .retained_item(TARGET, kind, 1)
        .ok_or("item")?;
    item.expires_at = 4000;
    executor.state.mailboxes.restore_item(TARGET, kind, 1, item);
    f.core.commit_staged_batch().await?;
    f.coordinator.batch_applied(f.core.context_mut()?);
    assert!(!f.coordinator.loaded());
    assert_eq!(f.coordinator.counters().violations, 1);
    assert_eq!(f.executor()?.state.mailboxes.item_count(), 2);
    f.restart().await?;
    assert_eq!(f.executor()?.state.mailboxes.item_count(), 0);
    Ok(())
}
