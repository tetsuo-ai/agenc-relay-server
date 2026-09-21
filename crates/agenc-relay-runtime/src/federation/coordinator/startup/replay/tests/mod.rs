//! A cancelled replay read keeps its charge until its exact sealed result is discarded.
#![forbid(unsafe_code)]

use super::*;
use crate::budget::{BackingReservationPort, MemoryBudget};
use crate::e2ee::coordinator::CompanionCoordinator;
use crate::test_support::{StateCoreFixture, TestResult};
use agenc_relay_storage::e2ee_records::DELIVERY_RECOVERY_ROW_KIND;
use agenc_relay_storage::e2ee_records::delivery_recovery::outbox::replay::{
    ReplayLedgerRow, ReplayOwner, ReplayOwnerFields,
};
use agenc_relay_storage::e2ee_records::delivery_recovery::{
    CutPhase, DeliveryCursor, DeliveryOwner, DeliveryRecoveryRow, DeliveryScope,
    DeliveryScopeFields, LastAcknowledged, fixture_body,
};
use agenc_relay_storage::{InitialStorageRecord, TableId};
use std::sync::Arc;

fn seeded() -> TestResult<(
    StateCoreFixture,
    FederationCoordinator,
    ReplayRestoreRequest,
)> {
    let DeliveryRecoveryRow::Owner(template) = DeliveryRecoveryRow::decode(&fixture_body(7)?)?
    else {
        return Err("owner fixture".into());
    };
    let scope = DeliveryScope::new(DeliveryScopeFields {
        network_id: [31; 32],
        coordinator_server_id: [32; 16],
        coordinator_incarnation: [33; 16],
        coordinator_recovery_epoch: [34; 16],
        target_server_id: [2; 16],
        target_incarnation: [4; 16],
        covered_base_client_resync_epoch: 0,
    })?;
    let last = LastAcknowledged::At {
        sequence: 0,
        event_id: [8; 16],
    };
    let owner = DeliveryRecoveryRow::Owner(DeliveryOwner::new(
        scope,
        DeliveryCursor::new(0, 1, last)?,
        *template.cut(),
        CutPhase::Ready,
    )?);
    let replay = ReplayLedgerRow::Owner(ReplayOwner::new(ReplayOwnerFields {
        scope,
        generation: 0,
        through: 0,
        event_id: [8; 16],
        first_retained: 1,
        retained_rows: 0,
        retained_bytes: 0,
        trusted_unix_seconds: None,
    })?);
    let value = PersistentRecordValue::new(
        TableId::E2eeState,
        DELIVERY_RECOVERY_ROW_KIND,
        1,
        0,
        None,
        Vec::new(),
        replay.encode()?,
    )?;
    let records = vec![InitialStorageRecord::new(
        TableId::E2eeState,
        replay.key()?,
        1,
        value.encode()?,
    )?];
    let mut fixture =
        StateCoreFixture::with_registration_router_and_records(vec![44; 65_536], records)?;
    let identity = &fixture.identity;
    let mut coordinator = FederationCoordinator::new(
        crate::federation::coordinator::CoordinatorConfig {
            network_id: identity.network_id,
            server_id: identity.server_id,
            server_name: "coordinator.example".into(),
            recovery_epoch: identity.recovery_epoch,
            query_cursor_key: [21; 32],
            process_nonce: [22; 16],
            outbox_bytes_per_edge: 1 << 20,
            outbox_objects_per_edge: 64,
        },
        Vec::new(),
        Arc::new(crate::test_support::TestChannelKeyVerifier),
        crate::bridge::crypto::ChannelKeyVerifierRecord::new([7; 16], [1; 32]),
    );
    coordinator.install_companion_executor(
        CompanionCoordinator::new(
            *identity.network_id.as_bytes(),
            identity.server_id,
            "coordinator.example".into(),
        ),
        identity.server_incarnation,
    )?;
    let executor = coordinator.companion_exec.as_mut().ok_or("executor")?;
    let value = PersistentRecordValue::new(
        TableId::E2eeState,
        DELIVERY_RECOVERY_ROW_KIND,
        1,
        0,
        None,
        Vec::new(),
        owner.encode()?,
    )?;
    executor.admit_restored(TableId::E2eeState, &owner.key()?, &value);
    let context = fixture.context_mut()?;
    let request = executor
        .next_restored_replay(
            &context.backing_reservations(),
            context.head().storage_commit_sequence,
        )?
        .ok_or("replay owner request")?;
    Ok((fixture, coordinator, request))
}

async fn cancelled(restart: bool) -> TestResult {
    let (mut fixture, mut coordinator, request) = seeded()?;
    let budget = Arc::new(MemoryBudget::new(128 * 1024 * 1024));
    let port = BackingReservationPort::new(Arc::clone(&budget));
    let raw = port.reserve(RAW_BYTES)?;
    let decode = port.reserve(DECODE_BYTES)?;
    let id = fixture
        .context_mut()?
        .submit_storage_read(request.plan()?)?;
    coordinator.loader.started = true;
    coordinator.loader.pending = Some(id);
    coordinator.loader.replay.read = Some(Box::new(ReadOwner {
        id,
        request,
        _raw: raw,
        _decode: decode,
    }));
    let charged = budget.charged();
    let completion = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        fixture.next_storage_read(),
    )
    .await??;
    assert_eq!(completion.read_id, id);
    let result = completion
        .result
        .as_ref()
        .map_err(|error| format!("sealed read: {error:?}"))?;
    assert_eq!(result.records.len(), 1);
    assert!(
        !result
            .records
            .first()
            .ok_or("sealed replay owner")?
            .sealed_record
            .is_empty()
    );
    if restart {
        super::super::begin(&mut coordinator, fixture.context_mut()?);
    } else {
        super::super::fail_restore(&mut coordinator);
    }
    assert!(coordinator.loader.owns(id));
    assert_eq!(budget.charged(), charged);
    let violations = coordinator.counters.violations;
    let wrong = StorageReadCompletionMessage {
        read_id: StorageReadId::new(id.get().checked_add(1).ok_or("read id overflow")?),
        result: Err(StorageError::Unavailable),
    };
    super::super::read_completed(&mut coordinator, fixture.context_mut()?, wrong);
    assert!(coordinator.loader.owns(id));
    assert_eq!(budget.charged(), charged);
    super::super::read_completed(&mut coordinator, fixture.context_mut()?, completion);
    assert_eq!(budget.charged(), 0);
    assert!(!coordinator.loader.owns(id));
    assert!(coordinator.loader.failed);
    assert!(!coordinator.loader.complete);
    assert!(!coordinator.loader.rebuilt);
    assert!(coordinator.loader.replay.read.is_none());
    assert_eq!(coordinator.counters.violations, violations);
    Ok(())
}

#[tokio::test]
async fn replay_cancellation_keeps_its_lease_until_the_exact_sealed_result_drops() -> TestResult {
    cancelled(false).await
}

#[tokio::test]
async fn repeated_startup_preserves_a_submitted_replay_read_owner() -> TestResult {
    cancelled(true).await
}
