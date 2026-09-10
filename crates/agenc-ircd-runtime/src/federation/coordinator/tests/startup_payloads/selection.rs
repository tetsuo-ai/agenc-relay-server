//! Mailbox references are complete before the runtime selects body residency.
#![forbid(unsafe_code)]
use super::*;
use agenc_ircd_storage::e2ee_records::MailboxKind;
use helpers::*;

#[tokio::test]
async fn a_mailbox_application_remains_resident_with_its_memory_owner() -> TestResult {
    let mut core = StateCoreFixture::with_registration_router(entropy_script())?;
    let bytes = application(*core.identity.network_id.as_bytes())?;
    let id = *ObjectId::compute(&bytes).as_bytes();
    let mut writes = mailbox(&bytes, MailboxKind::Application)?;
    writes.push(CompanionCoordinator::object_write(&bytes).map_err(|e| format!("object: {e:?}"))?);
    commit(&mut core, writes).await?;
    let budget = core.context_mut()?.backing_budget_for_test();
    let baseline = budget.charged();
    let mut coordinator = empty_coordinator(&core)?;
    coordinator.startup(core.context_mut()?);
    drive(&mut coordinator, &mut core).await?;
    assert!(coordinator.loaded());
    let executor = coordinator.companion_executor().ok_or("executor")?;
    assert_eq!(executor.state.objects.get(&id), Some(&bytes));
    assert_eq!(executor.state.mailboxes.item_count(), 1);
    assert_eq!(executor.state.object_memory.len(), 1);
    assert!(budget.charged() > baseline);
    drop(coordinator);
    assert_eq!(budget.charged(), baseline);
    Ok(())
}

#[tokio::test]
async fn a_missing_or_wrong_kind_mailbox_body_refuses_composed_startup() -> TestResult {
    for missing in [true, false] {
        let mut core = StateCoreFixture::with_registration_router(entropy_script())?;
        let bytes = application(*core.identity.network_id.as_bytes())?;
        let mut writes = mailbox(
            &bytes,
            if missing {
                MailboxKind::Application
            } else {
                MailboxKind::Welcome
            },
        )?;
        if !missing {
            writes.push(
                CompanionCoordinator::object_write(&bytes).map_err(|e| format!("object: {e:?}"))?,
            );
        }
        commit(&mut core, writes).await?;
        let mut coordinator = empty_coordinator(&core)?;
        coordinator.startup(core.context_mut()?);
        drive(&mut coordinator, &mut core).await?;
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

#[tokio::test]
async fn metadata_cannot_arrive_after_the_selective_object_phase_was_sealed() -> TestResult {
    let mut core = StateCoreFixture::with_registration_router(entropy_script())?;
    let bytes = application(*core.identity.network_id.as_bytes())?;
    let mut coordinator = CompanionCoordinator::new(
        *core.identity.network_id.as_bytes(),
        core.identity.server_id,
        COORDINATOR_NAME.into(),
    );
    coordinator.select_restored_objects(core.context_mut()?.backing_reservations())?;
    for write in mailbox(&bytes, MailboxKind::Application)? {
        if let crate::state_core::durable::AccountServiceDurableWrite::Put {
            table,
            key,
            plaintext,
        } = write
        {
            coordinator.admit_restored(
                table,
                &key,
                &PersistentRecordValue::decode(table, &plaintext)?,
            );
        }
    }
    assert!(coordinator.finish_restore().is_err());
    assert!(coordinator.state.objects.is_empty());
    Ok(())
}
