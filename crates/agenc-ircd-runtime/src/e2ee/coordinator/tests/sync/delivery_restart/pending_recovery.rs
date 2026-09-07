//! Sealed Pending pages, original cursors, and cut-local retirement survive restart.
#![forbid(unsafe_code)]

mod fetch;

use super::*;
use agenc_ircd_storage::e2ee_records::delivery_recovery::{
    CUT_PAGE_PREFIX, CutPhase, DeliveryOwner, PendingDeadline, PendingDeadlineFields,
    RetirementReason,
};

async fn pending_fixture(count: usize) -> TestResult<RestartFixture> {
    let storage = StateCoreFixture::new(vec![44; 65_536])?;
    let mut coordinator = CompanionCoordinator::new(
        *storage.identity.network_id.as_bytes(),
        storage.identity.server_id,
        SERVER_NAME.into(),
    );
    coordinator.configure_delivery_identity(
        storage.identity.server_incarnation,
        storage.identity.recovery_epoch,
    )?;
    for sequence in 0..count {
        let mut conversation = [0; 32];
        conversation[..8].copy_from_slice(&u64::try_from(sequence)?.to_be_bytes());
        let bytes = snapshot_route(*storage.identity.network_id.as_bytes(), conversation, 40)?;
        let object = object_id(&bytes);
        coordinator
            .state
            .conversations
            .entry(conversation)
            .or_default()
            .route_object_id = object;
        coordinator.state.objects.insert(object, bytes);
        coordinator
            .state
            .entitlements
            .set_channel(home(), conversation, true);
    }
    let mut fixture = RestartFixture {
        storage,
        coordinator,
        host: FakeHost::default(),
        entropy: Counter(60),
        keys: Vec::new(),
        copies: Vec::new(),
    };
    let actions = fixture.frame(CompanionFrame::Resume {
        coordinator_server_id: *fixture.storage.identity.server_id.as_bytes(),
        server_incarnation: INCARNATION,
        delivery_generation: 0,
        last: None,
    })?;
    let _ = fixture.publish_cut(actions).await?;
    Ok(fixture)
}

fn owner(fixture: &RestartFixture) -> TestResult<DeliveryOwner> {
    fixture
        .coordinator
        .state
        .streams
        .get(&home())
        .and_then(|stream| stream.owner.clone())
        .ok_or_else(|| "exact durable owner missing".into())
}

async fn read_value(
    fixture: &mut RestartFixture,
    table: TableId,
    key: &StoredKey,
) -> TestResult<(u64, PersistentRecordValue)> {
    let id = fixture
        .storage
        .context_mut()?
        .submit_storage_read(ReadPlan::exact(table, key.clone()))?;
    let message = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        fixture.storage.next_storage_read(),
    )
    .await??;
    assert_eq!(id, message.read_id);
    let result = message.result?;
    assert!(!result.truncated);
    assert_eq!(result.records.len(), 1);
    let row = result.records.first().ok_or("exact sealed row")?;
    assert!(row.key == *key);
    let plaintext =
        fixture
            .storage
            .context_mut()?
            .open_storage_plaintext(table, key, &row.sealed_record)?;
    Ok((
        result.storage_commit_sequence,
        PersistentRecordValue::decode(table, plaintext.expose_for_storage_codec())?,
    ))
}

async fn reconstruct(fixture: &mut RestartFixture) -> TestResult<CompanionCoordinator> {
    let mut restored = CompanionCoordinator::new(
        *fixture.storage.identity.network_id.as_bytes(),
        fixture.storage.identity.server_id,
        SERVER_NAME.into(),
    );
    restored.configure_delivery_identity(
        fixture.storage.identity.server_incarnation,
        fixture.storage.identity.recovery_epoch,
    )?;
    let pinned = fixture
        .storage
        .context_mut()?
        .head()
        .storage_commit_sequence;
    for (table, key) in fixture.keys.clone() {
        let (position, value) = read_value(fixture, table, &key).await?;
        assert_eq!(position, pinned);
        restored.admit_restored(table, &key, &value);
    }
    for _ in 0..agenc_ircd_storage::e2ee_records::delivery_recovery::MAX_SNAPSHOT_PAGES + 1 {
        let Some(key) = restored.next_restored_delivery_page(&fixture.host.backing)? else {
            for (table, key) in fixture.keys.clone().into_iter().filter(|(table, key)| {
                *table == TableId::E2eeState && key.as_bytes().starts_with(CUT_PAGE_PREFIX)
            }) {
                let (position, value) = read_value(fixture, table, &key).await?;
                assert_eq!(position, pinned);
                restored.inventory_restored_delivery_page(&key, &value)?;
            }
            restored.finish_restore()?;
            return Ok(restored);
        };
        let (position, value) = read_value(fixture, TableId::E2eeState, &key).await?;
        assert_eq!(position, pinned);
        restored.admit_restored_delivery_page(&key, &value)?;
    }
    Err("restored page count exceeded bound".into())
}

#[tokio::test]
async fn sealed_pending_restart_preserves_full_cut_and_original_random_cursors() -> TestResult {
    let mut fixture = pending_fixture(65).await?;
    let expected = owner(&fixture)?;
    let original = fixture
        .coordinator
        .peer_sync(home())
        .and_then(|sync| sync.snapshot.as_ref())
        .ok_or("published snapshot")?;
    let cursors: Vec<_> = (0..original.capture.page_count())
        .map(|page| original.capture.cursor(page))
        .collect();
    let restored = reconstruct(&mut fixture).await?;
    let stream = restored
        .state
        .streams
        .get(&home())
        .ok_or("restored stream")?;
    assert_eq!(stream.owner.as_ref(), Some(&expected));
    assert_eq!(stream.acked, None);
    assert_eq!(stream.next_sequence, 0);
    let snapshot = restored
        .peer_sync(home())
        .and_then(|sync| sync.snapshot.as_ref())
        .ok_or("restored Pending snapshot")?;
    assert_eq!(snapshot.cut.token, expected.cut().token());
    assert_eq!(snapshot.capture.page_count(), 3);
    assert_eq!(
        (0..3)
            .map(|page| snapshot.capture.cursor(page))
            .collect::<Vec<_>>(),
        cursors
    );
    assert!(!restored.delivering(home()));
    assert_eq!(
        restored.state.conversations.len(),
        0,
        "authoritative cut was restored from its immutable rows, not current route state"
    );
    Ok(())
}

#[tokio::test]
async fn sealed_pending_zero_entry_cut_still_requires_its_exact_page() -> TestResult {
    let mut fixture = pending_fixture(0).await?;
    let expected = owner(&fixture)?;
    let restored = reconstruct(&mut fixture).await?;
    let snapshot = restored
        .peer_sync(home())
        .and_then(|sync| sync.snapshot.as_ref())
        .ok_or("empty snapshot")?;
    assert_eq!(snapshot.capture.page_count(), 1);
    assert_eq!(snapshot.capture.cursor(0), None);
    assert_eq!(snapshot.capture.total_object_bytes(), 0);
    assert_eq!(snapshot.cut.digest, expected.cut().digest());
    Ok(())
}

#[tokio::test]
async fn sealed_pending_clock_scope_loss_retires_only_after_exact_owner_receipt() -> TestResult {
    let mut fixture = pending_fixture(0).await?;
    let current = owner(&fixture)?;
    let CutPhase::Pending {
        offered_pages,
        deadline,
    } = current.phase()
    else {
        return Err("Pending owner".into());
    };
    let mut boot = deadline.boot_id();
    boot[0] ^= 1;
    let deadline = PendingDeadline::new(PendingDeadlineFields {
        boot_id: boot,
        offset_seconds: deadline.offset_seconds(),
        offset_nanoseconds: deadline.offset_nanoseconds(),
        deadline_seconds: deadline.deadline_seconds(),
        deadline_nanoseconds: deadline.deadline_nanoseconds(),
        observed_seconds: deadline.observed_seconds(),
        observed_nanoseconds: deadline.observed_nanoseconds(),
    })?;
    let lost = DeliveryOwner::new(
        *current.scope(),
        *current.cursor(),
        *current.cut(),
        CutPhase::Pending {
            offered_pages,
            deadline,
        },
    )?;
    fixture
        .commit(vec![super::super::super::super::delivery_owner::write(
            &lost,
        )?])
        .await?;
    let mut restored = reconstruct(&mut fixture).await?;
    let candidate = restored
        .next_restored_retirement()?
        .ok_or("clock-loss retirement")?;
    candidate.validate(&restored)?;
    assert!(
        restored
            .peer_sync(home())
            .and_then(|sync| sync.snapshot.as_ref())
            .is_some()
    );
    fixture.commit(vec![candidate.write()?]).await?;
    candidate.apply(&mut restored)?;
    let stream = restored
        .state
        .streams
        .get(&home())
        .ok_or("retained stream")?;
    let retired = stream.owner.as_ref().ok_or("retained Owner")?;
    assert_eq!(retired.scope(), current.scope());
    assert_eq!(retired.cursor(), current.cursor());
    assert_eq!(retired.cut(), current.cut());
    assert_eq!(
        retired.phase(),
        CutPhase::Retired(RetirementReason::ClockScopeLost)
    );
    assert!(
        restored
            .peer_sync(home())
            .and_then(|sync| sync.snapshot.as_ref())
            .is_none()
    );
    assert!(!restored.delivering(home()));
    Ok(())
}
