//! Exact cancelled read ownership survives failure and drains its queued sealed result.
#![forbid(unsafe_code)]

use super::*;
use crate::budget::{BackingReservationPort, MemoryBudget};
use crate::sync::Arc;
use crate::test_support::{StateCoreFixture, TestResult};
use agenc_ircd_storage::InitialStorageRecord;
use agenc_ircd_storage::e2ee_records::{
    MAILBOX_SEQUENCE_ROW_KIND, MailboxKind, MailboxSequenceRow,
};

fn coordinator(fixture: &StateCoreFixture) -> FederationCoordinator {
    FederationCoordinator::new(
        crate::federation::coordinator::CoordinatorConfig {
            network_id: fixture.identity.network_id,
            server_id: fixture.identity.server_id,
            server_name: "coordinator.example".into(),
            recovery_epoch: fixture.identity.recovery_epoch,
            query_cursor_key: [21; 32],
            process_nonce: [22; 16],
            outbox_bytes_per_edge: 1 << 20,
            outbox_objects_per_edge: 64,
        },
        Vec::new(),
        std::sync::Arc::new(crate::test_support::TestChannelKeyVerifier),
        crate::bridge::crypto::ChannelKeyVerifierRecord::new([7; 16], [1; 32]),
    )
}

fn seeded() -> TestResult<(StateCoreFixture, StoredKey)> {
    let row = MailboxSequenceRow::new([1; 32], [2; 16], MailboxKind::Application, 1)?;
    let key = row.key()?;
    let value = PersistentRecordValue::new(
        TableId::E2eeState,
        MAILBOX_SEQUENCE_ROW_KIND,
        1,
        0,
        None,
        Vec::new(),
        row.encode()?,
    )?
    .encode()?;
    let record = InitialStorageRecord::new(TableId::E2eeState, key.clone(), 1, value)?;
    let fixture =
        StateCoreFixture::with_registration_router_and_records(vec![44; 65_536], vec![record])?;
    Ok((fixture, key))
}

fn charged_owner(
    id: StorageReadId,
    key: StoredKey,
    port: &BackingReservationPort,
) -> TestResult<ReadOwner> {
    let raw = port.reserve(RAW_READ_BYTES)?;
    let decode = (0..DECODE_BUFFERS)
        .map(|_| port.reserve(DECODE_BYTES))
        .collect::<Result<Vec<_>, _>>()?;
    let decode = decode.try_into().map_err(|_| "exact decode lease count")?;
    Ok(ReadOwner {
        id,
        key,
        inventory: false,
        _raw: raw,
        _decode: decode,
    })
}

#[tokio::test]
async fn failed_startup_retains_its_exact_read_lease_until_the_sealed_result_is_discarded()
-> TestResult {
    let (mut fixture, key) = seeded()?;
    let mut coordinator = coordinator(&fixture);
    let budget = Arc::new(MemoryBudget::new(512 * 1_024 * 1_024));
    let port = BackingReservationPort::new(Arc::clone(&budget));
    let id = fixture
        .context_mut()?
        .submit_storage_read(ReadPlan::exact(TableId::E2eeState, key.clone()))?;
    coordinator.loader.started = true;
    coordinator.loader.pending = Some(id);
    coordinator.loader.delivery.read = Some(charged_owner(id, key, &port)?);
    let charged = budget.charged();
    assert!(charged > 0);
    let completion = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        fixture.next_storage_read(),
    )
    .await??;
    assert_eq!(completion.read_id, id);
    let rows = &completion
        .result
        .as_ref()
        .map_err(|error| format!("exact read: {error:?}"))?
        .records;
    assert_eq!(rows.len(), 1);
    assert!(
        !rows
            .first()
            .ok_or("sealed result")?
            .sealed_record
            .is_empty()
    );
    super::super::fail_restore(&mut coordinator);
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
    assert!(coordinator.loader.delivery.read.is_none());
    assert_eq!(
        coordinator.counters.violations, violations,
        "cancelled data must not be decoded as a cut page"
    );
    Ok(())
}

#[tokio::test]
async fn repeated_startup_cannot_replace_a_submitted_read_owner() -> TestResult {
    let (mut fixture, key) = seeded()?;
    let mut coordinator = coordinator(&fixture);
    let budget = Arc::new(MemoryBudget::new(512 * 1_024 * 1_024));
    let port = BackingReservationPort::new(Arc::clone(&budget));
    let id = fixture
        .context_mut()?
        .submit_storage_read(ReadPlan::exact(TableId::E2eeState, key.clone()))?;
    coordinator.loader.started = true;
    coordinator.loader.pending = Some(id);
    coordinator.loader.delivery.read = Some(charged_owner(id, key, &port)?);
    let charged = budget.charged();
    super::super::begin(&mut coordinator, fixture.context_mut()?);
    assert!(coordinator.loader.failed);
    assert!(coordinator.loader.owns(id));
    assert_eq!(budget.charged(), charged);
    let completion = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        fixture.next_storage_read(),
    )
    .await??;
    assert_eq!(completion.read_id, id);
    super::super::read_completed(&mut coordinator, fixture.context_mut()?, completion);
    assert_eq!(budget.charged(), 0);
    assert!(!coordinator.loader.complete);
    Ok(())
}
