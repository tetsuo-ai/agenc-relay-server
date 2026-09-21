//! A companion page read admits exactly the row it asked for: one page at most, never a
//! truncated empty page, only `e2ee_state` rows within its lease, and for an inventory scan only
//! keys inside the cut-page prefix.
#![forbid(unsafe_code)]

use super::*;
use crate::budget::{BackingReservationPort, MemoryBudget};
use crate::sync::Arc;
use crate::test_support::{StateCoreFixture, TestResult};
use agenc_relay_storage::ReadRecord;

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

/// A coordinator whose delivery loader owns a read of `key`, inventory or exact.
fn owning(
    fixture: &StateCoreFixture,
    key: StoredKey,
    inventory: bool,
) -> TestResult<(FederationCoordinator, StorageReadId)> {
    let mut coordinator = coordinator(fixture);
    let budget = Arc::new(MemoryBudget::new(512 * 1_024 * 1_024));
    let port = BackingReservationPort::new(budget);
    let raw = port.reserve(RAW_READ_BYTES)?;
    let decode = (0..DECODE_BUFFERS)
        .map(|_| port.reserve(DECODE_BYTES))
        .collect::<Result<Vec<_>, _>>()?;
    let decode = decode.try_into().map_err(|_| "exact decode lease count")?;
    let id = StorageReadId::new(7);
    coordinator.loader.started = true;
    coordinator.loader.pending = Some(id);
    coordinator.loader.delivery.read = Some(ReadOwner {
        id,
        key,
        inventory,
        _raw: raw,
        _decode: decode,
    });
    Ok((coordinator, id))
}

fn row(table: TableId, key: StoredKey, bytes: usize) -> ReadRecord {
    ReadRecord {
        table,
        key,
        sealed_record: vec![1; bytes],
    }
}

fn page(
    id: StorageReadId,
    records: Vec<ReadRecord>,
    truncated: bool,
) -> StorageReadCompletionMessage {
    StorageReadCompletionMessage {
        read_id: id,
        result: Ok(agenc_relay_storage::ReadResult {
            storage_commit_sequence: 0,
            records,
            truncated,
        }),
    }
}

fn inside() -> TestResult<StoredKey> {
    let mut bytes = CUT_PAGE_PREFIX.to_vec();
    bytes.extend_from_slice(&[5; 16]);
    Ok(StoredKey::new(bytes)?)
}

fn below() -> TestResult<StoredKey> {
    let mut bytes = CUT_PAGE_PREFIX.to_vec();
    let first = bytes.first_mut().ok_or("prefix byte")?;
    *first = first.checked_sub(1).ok_or("prefix underflow")?;
    Ok(StoredKey::new(bytes)?)
}

#[test]
fn an_inventory_page_admits_only_one_cut_page_row_inside_the_prefix() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![44; 65_536])?;
    let start = prefix_key().map_err(|_| "prefix key")?;
    let end = end_key().map_err(|_| "end key")?;
    let cases: Vec<(&str, Vec<ReadRecord>, bool)> = vec![
        (
            "two rows",
            vec![
                row(TableId::E2eeState, inside()?, 8),
                row(TableId::E2eeState, inside()?, 8),
            ],
            false,
        ),
        ("a truncated empty page", Vec::new(), true),
        (
            "another table",
            vec![row(TableId::FederationPeer, inside()?, 8)],
            false,
        ),
        (
            "a row over the decode lease",
            vec![row(TableId::E2eeState, inside()?, DECODE_BYTES + 1)],
            false,
        ),
        (
            "a key below the prefix",
            vec![row(TableId::E2eeState, below()?, 8)],
            false,
        ),
        (
            "a key at the end of the prefix",
            vec![row(TableId::E2eeState, end, 8)],
            false,
        ),
    ];
    for (name, records, truncated) in cases {
        let (mut coordinator, id) = owning(&fixture, start.clone(), true)?;
        let violations = coordinator.counters.violations;
        completed(
            &mut coordinator,
            fixture.context_mut()?,
            page(id, records, truncated),
        );
        assert!(coordinator.loader.failed, "{name}");
        assert_eq!(coordinator.counters.violations, violations + 1, "{name}");
        assert!(coordinator.loader.delivery.read.is_none(), "{name}");
    }
    Ok(())
}

#[test]
fn an_exact_page_read_admits_only_its_own_single_row() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![44; 65_536])?;
    let key = inside()?;
    let cases: Vec<(&str, Vec<ReadRecord>, bool)> = vec![
        ("no row", Vec::new(), false),
        (
            "a truncated row",
            vec![row(TableId::E2eeState, key.clone(), 8)],
            true,
        ),
        (
            "another key",
            vec![row(TableId::E2eeState, below()?, 8)],
            false,
        ),
    ];
    for (name, records, truncated) in cases {
        let (mut coordinator, id) = owning(&fixture, key.clone(), false)?;
        completed(
            &mut coordinator,
            fixture.context_mut()?,
            page(id, records, truncated),
        );
        assert!(coordinator.loader.failed, "{name}");
    }
    Ok(())
}

#[test]
fn a_resource_refused_page_read_is_retried_and_a_stale_pin_fails() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![44; 65_536])?;
    let start = prefix_key().map_err(|_| "prefix key")?;
    let (mut coordinator, id) = owning(&fixture, start.clone(), true)?;
    completed(
        &mut coordinator,
        fixture.context_mut()?,
        StorageReadCompletionMessage {
            read_id: id,
            result: Err(StorageError::QueueFull),
        },
    );
    assert!(!coordinator.loader.failed);
    assert!(coordinator.loader.delivery.read.is_none());
    let (mut coordinator, id) = owning(&fixture, start, true)?;
    coordinator.loader.pinned_commit = Some(9);
    completed(
        &mut coordinator,
        fixture.context_mut()?,
        page(id, Vec::new(), false),
    );
    assert!(coordinator.loader.failed, "a page from another commit");
    Ok(())
}
