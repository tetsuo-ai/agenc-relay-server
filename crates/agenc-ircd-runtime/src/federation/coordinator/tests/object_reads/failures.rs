//! Storage failure, cancellation, and rejected writes never publish an absent-object result.
#![forbid(unsafe_code)]
use super::*;

#[tokio::test]
async fn malformed_raw_reads_never_stage_a_response() -> TestResult {
    for fault in 0..6 {
        let mut f = Box::pin(Fixture::new(true)).await?;
        let sequence = f.next_sequence()?;
        f.submit()?;
        let mut message = f.next_read().await?;
        let result = message
            .result
            .as_mut()
            .map_err(|e| format!("read: {e:?}"))?;
        match fault {
            0 => result.truncated = true,
            1 => result.storage_commit_sequence += 1,
            2 => result.records.first_mut().ok_or("row")?.table = TableId::E2eeState,
            3 => {
                result.records.first_mut().ok_or("row")?.key =
                    agenc_ircd_storage::e2ee_records::object_key(&[99; 32])?
            }
            4 => {
                *result
                    .records
                    .first_mut()
                    .ok_or("row")?
                    .sealed_record
                    .last_mut()
                    .ok_or("bytes")? ^= 1
            }
            5 => {
                let row = result.records.first().ok_or("row")?;
                let duplicate = agenc_ircd_storage::ReadRecord {
                    table: row.table,
                    key: row.key.clone(),
                    sealed_record: row.sealed_record.clone(),
                };
                result.records.push(duplicate);
            }
            _ => return Err("fault".into()),
        }
        f.coordinator
            .storage_read_completed(f.core.context_mut()?, message);
        assert!(f.coordinator.companion_object_read.is_none());
        assert!(f.coordinator.pending.is_none());
        assert_eq!(f.handle.queued_bytes(), 0);
        assert_eq!(f.next_sequence()?, sequence);
        assert_eq!(f.coordinator.counters.violations, 1);
    }
    Ok(())
}

#[tokio::test]
async fn a_new_storage_commit_invalidates_a_pending_object_read() -> TestResult {
    let mut f = Box::pin(Fixture::new(true)).await?;
    f.submit()?;
    let message = f.next_read().await?;
    fixture::commit(
        &mut f.core,
        vec![CompanionCoordinator::object_write(&f.bytes).map_err(|e| format!("write: {e:?}"))?],
    )
    .await?;
    f.coordinator
        .storage_read_completed(f.core.context_mut()?, message);
    assert!(f.coordinator.pending.is_none());
    assert_eq!(f.handle.queued_bytes(), 0);
    assert_eq!(f.coordinator.counters.violations, 1);
    Ok(())
}

#[tokio::test]
async fn replacement_links_and_changed_base_epochs_cannot_receive_old_reads() -> TestResult {
    for replace in [false, true] {
        let mut f = Box::pin(Fixture::new(true)).await?;
        f.submit()?;
        let message = f.next_read().await?;
        let (replacement, _queue) = link_queue(1 << 20);
        let peer = f.coordinator.peers.get_mut(&PEER).ok_or("peer")?;
        if replace {
            peer.live = Some(LiveLink {
                link: LinkId::new(2),
                handle: replacement.clone(),
                incarnation: INCARNATION,
            });
        } else {
            peer.client_resync_epoch += 1;
        }
        f.coordinator
            .storage_read_completed(f.core.context_mut()?, message);
        assert!(f.coordinator.pending.is_none());
        assert_eq!(f.handle.queued_bytes(), 0);
        assert_eq!(replacement.queued_bytes(), 0);
        assert_eq!(f.coordinator.counters.violations, u64::from(!replace));
        if replace {
            assert!(f.coordinator.link_is_live(LinkId::new(2), PEER));
        }
    }
    Ok(())
}

#[tokio::test]
async fn quiescing_keeps_read_ownership_and_does_not_run_queued_requests() -> TestResult {
    let mut f = Box::pin(Fixture::new(true)).await?;
    let budget = f.core.context_mut()?.backing_budget_for_test();
    f.submit()?;
    companion::apply(
        &mut f.coordinator,
        f.core.context_mut()?,
        LinkId::new(1),
        PEER,
        crate::e2ee::coordinator::sync::Action::Execute(CompleteRequest {
            correlation: f.complete.correlation,
            request: f.complete.request.clone(),
            payload: None,
        }),
    )
    .map_err(|e| format!("queue: {e:?}"))?;
    let message = f.next_read().await?;
    let charged = budget.charged();
    f.core.context_mut()?.quiesce_for_test();
    assert!(f.coordinator.owns_storage_read(message.read_id));
    assert_eq!(budget.charged(), charged);
    f.coordinator
        .storage_read_completed(f.core.context_mut()?, message);
    assert!(budget.charged() < charged);
    assert!(f.coordinator.companion_object_read.is_none());
    assert!(f.coordinator.pending.is_none());
    assert_eq!(f.handle.queued_bytes(), 0);
    assert_eq!(f.coordinator.counters.violations, 0);
    Ok(())
}

#[tokio::test]
async fn byte_budget_refusal_before_io_or_after_decode_releases_owned_bytes() -> TestResult {
    for before_io in [true, false] {
        let mut f = Box::pin(Fixture::new(true)).await?;
        let budget = f.core.context_mut()?.backing_budget_for_test();
        let baseline = budget.charged();
        let message = if before_io {
            None
        } else {
            f.submit()?;
            Some(f.next_read().await?)
        };
        let held = f
            .core
            .context_mut()?
            .reserve_output_backing(usize::try_from(
                budget.available().checked_sub(8192).ok_or("headroom")?,
            )?)?;
        if let Some(message) = message {
            f.coordinator
                .storage_read_completed(f.core.context_mut()?, message);
            assert_eq!(f.coordinator.counters.violations, 1);
        } else {
            assert!(f.submit().is_err());
            assert!(
                tokio::time::timeout(
                    std::time::Duration::from_millis(20),
                    f.core.next_storage_read()
                )
                .await
                .is_err()
            );
        }
        assert!(f.coordinator.companion_object_read.is_none());
        assert!(f.coordinator.pending.is_none());
        assert_eq!(f.handle.queued_bytes(), 0);
        drop(held);
        assert_eq!(budget.charged(), baseline);
    }
    Ok(())
}

#[tokio::test]
async fn rejecting_the_staged_write_keeps_sequence_and_releases_body_backing() -> TestResult {
    let mut f = Box::pin(Fixture::new(true)).await?;
    let budget = f.core.context_mut()?.backing_budget_for_test();
    let baseline = budget.charged();
    let sequence = f.next_sequence()?;
    f.submit()?;
    f.resolve().await?;
    assert!(budget.charged() > baseline);
    f.core
        .state_mut()?
        .reject_fixture_batch_before_submission(agenc_ircd_storage::StorageError::QueueFull)?;
    f.coordinator.batch_rejected(f.core.context_mut()?);
    assert_eq!(f.next_sequence()?, sequence);
    assert_eq!(f.handle.queued_bytes(), 0);
    assert_eq!(budget.charged(), baseline);
    assert!(
        !f.executor()?
            .state
            .results
            .contains_key(ObjectId::compute(&f.complete.request).as_bytes())
    );
    assert!(!f.executor()?.state.objects.contains_key(&f.object_id));
    Ok(())
}

#[tokio::test]
async fn a_stalled_writer_owns_the_body_reservation_after_the_receipt() -> TestResult {
    let mut f = Box::pin(Fixture::new(true)).await?;
    let budget = f.core.context_mut()?.backing_budget_for_test();
    let baseline = budget.charged();
    f.submit()?;
    f.resolve().await?;
    assert!(budget.charged() > baseline);
    f.commit_pending().await?;
    assert!(f.handle.queued_bytes() > 0);
    assert!(budget.charged() > baseline);
    drop(f.queue);
    assert_eq!(budget.charged(), baseline);
    Ok(())
}
