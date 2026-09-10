//! Submitted startup reads keep their exact owners across failure and shutdown.
#![forbid(unsafe_code)]
use super::*;
use crate::bridge::{StorageReadCompletionMessage, StorageReadId};
use helpers::*;

#[tokio::test]
async fn repeated_startup_keeps_the_first_table_read_owner_until_completion() -> TestResult {
    let mut core = StateCoreFixture::with_registration_router(entropy_script())?;
    let budget = core.context_mut()?.backing_budget_for_test();
    let baseline = budget.charged();
    let mut coordinator = empty_coordinator(&core)?;
    coordinator.startup(core.context_mut()?);
    let message = next(&mut core).await?;
    let charged = budget.charged();
    assert!(charged > baseline);
    coordinator.startup(core.context_mut()?);
    assert!(coordinator.owns_storage_read(message.read_id));
    assert_eq!(budget.charged(), charged);
    coordinator.storage_read_completed(core.context_mut()?, message);
    assert_eq!(budget.charged(), baseline);
    assert_eq!(coordinator.counters().violations, 1);
    assert!(!coordinator.loaded());
    Ok(())
}

#[tokio::test]
async fn wrong_read_id_and_quiescing_do_not_transfer_ownership_or_start_more_reads() -> TestResult {
    let mut core = StateCoreFixture::with_registration_router(entropy_script())?;
    let budget = core.context_mut()?.backing_budget_for_test();
    let baseline = budget.charged();
    let mut coordinator = empty_coordinator(&core)?;
    coordinator.startup(core.context_mut()?);
    let message = next(&mut core).await?;
    let id = message.read_id;
    let charged = budget.charged();
    coordinator.storage_read_completed(
        core.context_mut()?,
        StorageReadCompletionMessage {
            read_id: StorageReadId::new(id.get() + 1),
            result: Err(agenc_ircd_storage::StorageError::Unavailable),
        },
    );
    assert!(coordinator.owns_storage_read(id));
    assert_eq!(budget.charged(), charged);
    core.context_mut()?.quiesce_for_test();
    coordinator.storage_read_completed(core.context_mut()?, message);
    assert_eq!(budget.charged(), baseline);
    assert_eq!(coordinator.counters().violations, 0);
    assert!(!coordinator.loaded());
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(20),
            core.next_storage_read()
        )
        .await
        .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn storage_retry_releases_the_old_owner_before_reserving_its_replacement() -> TestResult {
    let mut core = StateCoreFixture::with_registration_router(entropy_script())?;
    let budget = core.context_mut()?.backing_budget_for_test();
    let mut coordinator = empty_coordinator(&core)?;
    coordinator.startup(core.context_mut()?);
    let mut message = next(&mut core).await?;
    let old = message.read_id;
    let held = core.context_mut()?.reserve_output_backing(usize::try_from(
        budget.available().checked_sub(8192).ok_or("headroom")?,
    )?)?;
    let charged = budget.charged();
    message.result = Err(agenc_ircd_storage::StorageError::Unavailable);
    coordinator.storage_read_completed(core.context_mut()?, message);
    assert_eq!(budget.charged(), charged);
    let replacement = next(&mut core).await?;
    assert_ne!(replacement.read_id, old);
    assert!(coordinator.owns_storage_read(replacement.read_id));
    drop(held);
    coordinator.storage_read_completed(core.context_mut()?, replacement);
    drive(&mut coordinator, &mut core).await?;
    assert!(coordinator.loaded());
    Ok(())
}

#[tokio::test]
async fn memory_refusal_before_the_first_read_can_retry_after_capacity_returns() -> TestResult {
    let mut core = StateCoreFixture::with_registration_router(entropy_script())?;
    let budget = core.context_mut()?.backing_budget_for_test();
    let held = core.context_mut()?.reserve_output_backing(usize::try_from(
        budget.available().checked_sub(8192).ok_or("headroom")?,
    )?)?;
    let charged = budget.charged();
    let mut coordinator = empty_coordinator(&core)?;
    coordinator.startup(core.context_mut()?);
    assert_eq!(budget.charged(), charged);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(20),
            core.next_storage_read()
        )
        .await
        .is_err()
    );
    drop(held);
    coordinator.continue_restore(core.context_mut()?);
    drive(&mut coordinator, &mut core).await?;
    assert!(coordinator.loaded());
    Ok(())
}

#[tokio::test]
async fn malformed_unselected_object_completions_fail_before_the_body_is_discarded() -> TestResult {
    for fault in 0..6 {
        let mut core = StateCoreFixture::with_registration_router(entropy_script())?;
        let bytes = application(*core.identity.network_id.as_bytes())?;
        commit(
            &mut core,
            vec![CompanionCoordinator::object_write(&bytes).map_err(|e| format!("object: {e:?}"))?],
        )
        .await?;
        let mut coordinator = empty_coordinator(&core)?;
        coordinator.startup(core.context_mut()?);
        let mut message = object_read(&mut coordinator, &mut core).await?;
        let result = message
            .result
            .as_mut()
            .map_err(|e| format!("read: {e:?}"))?;
        match fault {
            0 => result.records.first_mut().ok_or("row")?.table = TableId::E2eeState,
            1 => {
                result.records.first_mut().ok_or("row")?.key =
                    agenc_ircd_storage::StoredKey::new(vec![99; 32])?
            }
            2 => {
                *result
                    .records
                    .first_mut()
                    .ok_or("row")?
                    .sealed_record
                    .last_mut()
                    .ok_or("bytes")? ^= 1
            }
            3 => result.storage_commit_sequence += 1,
            4 => {
                result.records.clear();
                result.truncated = true;
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
        coordinator.storage_read_completed(core.context_mut()?, message);
        assert!(!coordinator.loaded());
        assert_eq!(coordinator.counters().violations, 1);
        assert!(
            coordinator
                .companion_executor()
                .ok_or("executor")?
                .state
                .objects
                .is_empty()
        );
    }
    Ok(())
}
