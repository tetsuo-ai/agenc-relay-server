//! Refused and late FETCH outcomes cannot invent an offered page or publish early.
#![forbid(unsafe_code)]

use super::*;
use agenc_relay_storage::e2ee_records::delivery_recovery::{DeliveryRecoveryRow, owner_key};

fn stage_fetch(
    fixture: &mut RestartFixture,
    writes: Vec<AccountServiceDurableWrite>,
) -> TestResult {
    let context = fixture.storage.context_mut()?;
    let plan = context.domain().plan_account_service_checkpoint()?;
    let revision = plan.resulting_revision().get();
    let writes = writes
        .into_iter()
        .map(|write| write.at_revision(revision))
        .collect::<Result<Vec<_>, _>>()?;
    context
        .stage_durable_with_account_service(
            plan,
            FanoutRequest::new(Vec::new(), Vec::new())?,
            None,
            0,
            writes,
        )
        .map_err(|error| format!("FETCH fixture stage: {error:?}"))?;
    Ok(())
}

fn pending_deadline(owner: &DeliveryOwner) -> TestResult<PendingDeadline> {
    let CutPhase::Pending { deadline, .. } = owner.phase() else {
        return Err("Pending deadline".into());
    };
    Ok(deadline)
}

#[tokio::test]
async fn a_rejected_fetch_batch_preserves_the_sealed_owner_and_original_deadline() -> TestResult {
    let mut fixture = pending_fixture(65).await?;
    let before = owner(&fixture)?;
    let frame = fetch_frame(&fixture, 1)?;
    let expected = expected_page(&fixture, 1)?;
    let actions = fixture.frame(frame.clone())?;
    let Some(Action::Stage { writes, work }) = actions.into_iter().next() else {
        return Err("exact FETCH advance".into());
    };
    fixture.coordinator.set_pending(work);
    stage_fetch(&mut fixture, writes)?;
    fixture
        .storage
        .state_mut()?
        .reject_fixture_batch_before_submission(
            agenc_relay_storage::StorageError::FilesystemRejected(
                agenc_relay_storage::FilesystemCause::IoFailure,
            ),
        )?;
    fixture.coordinator.batch_rejected();
    assert!(fixture.coordinator.batch_applied(Some(0))?.is_none());
    assert_eq!(owner(&fixture)?, before);
    let key = owner_key(&before.scope().target_server_id())?;
    let (_, value) = read_value(&mut fixture, TableId::E2eeState, &key).await?;
    assert_eq!(
        DeliveryRecoveryRow::decode_at(&key, value.body())?,
        DeliveryRecoveryRow::Owner(before.clone())
    );
    let retry = fixture.frame(frame)?;
    let Some(Action::Stage { writes, work }) = retry.into_iter().next() else {
        return Err("refused page must advance again, not replay an uncommitted boundary".into());
    };
    fixture.coordinator.set_pending(work);
    fixture.commit(writes).await?;
    let Some(Committed::Fetch(publication)) = fixture.coordinator.batch_applied(Some(0))? else {
        return Err("matching retry receipt".into());
    };
    let actions = publication.committed(&mut fixture.coordinator, NOW_MILLIS, &fixture.host)?;
    assert_eq!(frames(&actions)?, expected);
    let after = owner(&fixture)?;
    assert_eq!(after.cut(), before.cut());
    assert_eq!(after.cursor(), before.cursor());
    assert_eq!(
        pending_deadline(&after)?.deadline_seconds(),
        pending_deadline(&before)?.deadline_seconds()
    );
    assert_eq!(
        pending_deadline(&after)?.deadline_nanoseconds(),
        pending_deadline(&before)?.deadline_nanoseconds()
    );
    Ok(())
}

#[tokio::test]
async fn a_fetch_receipt_after_link_loss_keeps_durable_progress_without_publishing() -> TestResult {
    let mut fixture = pending_fixture(65).await?;
    let frame = fetch_frame(&fixture, 1)?;
    let expected = expected_page(&fixture, 1)?;
    let actions = fixture.frame(frame.clone())?;
    let Some(Action::Stage { writes, work }) = actions.into_iter().next() else {
        return Err("FETCH stage".into());
    };
    fixture.coordinator.set_pending(work);
    fixture.commit(writes).await?;
    fixture.coordinator.link_lost(home());
    let Some(Committed::Fetch(publication)) = fixture.coordinator.batch_applied(Some(0))? else {
        return Err("durable FETCH must retain its receipt through link loss".into());
    };
    assert!(
        publication
            .committed(&mut fixture.coordinator, NOW_MILLIS, &fixture.host)?
            .is_empty()
    );
    assert!(matches!(
        owner(&fixture)?.phase(),
        CutPhase::Pending {
            offered_pages: 2,
            ..
        }
    ));
    fixture.coordinator = reconstruct(&mut fixture).await?;
    fixture.host.clock = crate::e2ee::coordinator::delivery_owner::clock::sample();
    let read = fixture.frame(frame)?;
    let actions = complete_read(&mut fixture, read).await?;
    assert!(matches!(actions.as_slice(), [Action::SendPage(_)]));
    assert_eq!(frames(&actions)?, expected);
    Ok(())
}

#[tokio::test]
async fn a_wrong_cursor_or_skipped_page_cannot_change_the_sealed_offered_boundary() -> TestResult {
    let mut fixture = pending_fixture(65).await?;
    let before = owner(&fixture)?;
    let mut wrong = fetch_frame(&fixture, 1)?;
    let CompanionFrame::StateFetch { cursor, .. } = &mut wrong else {
        return Err("FETCH frame".into());
    };
    cursor[0] ^= 1;
    assert!(fixture.frame(wrong).is_err());
    let skipped = fetch_frame(&fixture, 2)?;
    assert!(fixture.frame(skipped).is_err());
    assert_eq!(owner(&fixture)?, before);
    assert!(fixture.coordinator.batch_applied(Some(0))?.is_none());
    let key = owner_key(&before.scope().target_server_id())?;
    let (_, value) = read_value(&mut fixture, TableId::E2eeState, &key).await?;
    assert_eq!(
        DeliveryRecoveryRow::decode_at(&key, value.body())?,
        DeliveryRecoveryRow::Owner(before)
    );
    Ok(())
}
