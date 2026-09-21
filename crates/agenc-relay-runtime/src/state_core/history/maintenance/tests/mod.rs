//! Retention cutoffs, bounded deletion, and replay-dependent control lifetime.
#![forbid(unsafe_code)]

use super::super::{HistoryChannel, HistoryRow, MAX_INDEX_BYTES, MAX_TOTAL_BYTES};
use super::*;
use crate::budget::MemoryBudget;
use crate::sync::Arc;
use agenc_relay_storage::history_records::{HistoryControlRecord, HistoryRowReference};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fixture() -> Result<(HistoryState, ChannelInstanceId), RuntimeError> {
    let budget = Arc::new(MemoryBudget::new(67_108_864));
    let id = ChannelInstanceId::from_bytes([1; 16]);
    let channel = HistoryChannel {
        control: HistoryControlRecord::empty(id, 1)?,
        rows: BTreeMap::new(),
        available_results: 0,
        _permit: acquire(&budget, INDEX_ENTRY_CHARGE)?,
    };
    Ok((
        HistoryState {
            enabled: true,
            coordinator: true,
            default: HistoryPolicy::OneHour,
            budget,
            maximum_bytes: MAX_TOTAL_BYTES,
            maximum_index_bytes: MAX_INDEX_BYTES,
            index_bytes: INDEX_ENTRY_CHARGE,
            message_count: 0,
            logical_bytes: 0,
            channels: BTreeMap::from([(id, channel)]),
            queries: Arc::new(AtomicUsize::new(0)),
        },
        id,
    ))
}

fn insert(
    history: &mut HistoryState,
    id: ChannelInstanceId,
    sequence: u64,
    expiry: u64,
) -> Result<(), RuntimeError> {
    let channel = history.channels.get_mut(&id).ok_or_else(corrupt)?;
    channel.rows.insert(
        sequence,
        HistoryRow {
            reference: HistoryRowReference {
                channel_sequence: sequence,
                message_id: [2; 16],
                received_unix_milliseconds: 1,
                expires_unix_milliseconds: expiry,
            },
            logical_bytes: 100,
            _permit: acquire(&history.budget, INDEX_ENTRY_CHARGE)?,
        },
    );
    channel.control.high_water_sequence = sequence;
    channel.control.retained_message_count += 1;
    channel.control.retained_logical_bytes += 100;
    history.message_count += 1;
    history.logical_bytes += 100;
    history.index_bytes += INDEX_ENTRY_CHARGE;
    Ok(())
}

#[test]
fn purge_deletes_at_most_one_thousand_rows_and_preserves_newer_messages() -> TestResult {
    let (mut history, id) = fixture()?;
    let budget = Arc::clone(&history.budget);
    for sequence in 1..=1_001 {
        insert(&mut history, id, sequence, 100_000)?;
    }
    let (_, purge) = history.prepare_purge(id, 1_002, [4; 32], 0, 1_002)?;
    history.committed(purge)?;
    insert(&mut history, id, 2_000, 100_000)?;
    assert!(!history.purge_complete(id));
    let domain = DomainState::new()?;
    let (writes, first) = history
        .prepare_cleanup(&domain, 1, 2_001)?
        .ok_or("first batch")?;
    assert_eq!(writes.len(), 1_001); // 1,000 deletions and the control postimage.
    history.committed(first)?;
    assert_eq!(history.message_count, 2);
    assert!(!history.purge_complete(id));
    let (writes, last) = history
        .prepare_cleanup(&domain, 1, 2_002)?
        .ok_or("last batch")?;
    assert_eq!(writes.len(), 2);
    history.committed(last)?;
    assert!(history.purge_complete(id));
    assert_eq!(history.message_count, 1);
    assert_eq!(history.logical_bytes, 100);
    assert_eq!(
        history
            .channels
            .get(&id)
            .ok_or("channel")?
            .rows
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        vec![2_000]
    );
    drop(history);
    assert_eq!(budget.charged(), 0);
    Ok(())
}

#[test]
fn expiry_is_inclusive_and_maintenance_continues_with_service_disabled() -> TestResult {
    let (mut history, id) = fixture()?;
    history.enabled = false;
    insert(&mut history, id, 1, 3_600_001)?;
    let domain = DomainState::new()?;
    assert!(history.prepare_cleanup(&domain, 3_600_000, 2)?.is_none());
    let (_, deletion) = history
        .prepare_cleanup(&domain, 3_600_001, 2)?
        .ok_or("expiry")?;
    history.committed(deletion)?;
    assert_eq!(history.message_count, 0);
    assert_eq!(history.logical_bytes, 0);
    assert_eq!(history.index_bytes, INDEX_ENTRY_CHARGE);
    assert!(history.channels.get(&id).ok_or("control")?.rows.is_empty());
    Ok(())
}

#[test]
fn empty_control_waits_for_live_queries_and_nonterminal_results() -> TestResult {
    let (mut history, id) = fixture()?;
    let domain = DomainState::new()?;
    history.queries.store(1, Ordering::Release);
    assert!(history.prepare_cleanup(&domain, 1, 2)?.is_none());
    history.queries.store(0, Ordering::Release);
    history
        .channels
        .get_mut(&id)
        .ok_or("control")?
        .available_results = 1;
    assert!(history.prepare_cleanup(&domain, 1, 2)?.is_none());
    history
        .channels
        .get_mut(&id)
        .ok_or("control")?
        .available_results = 0;
    let (writes, removal) = history.prepare_cleanup(&domain, 1, 2)?.ok_or("reclaim")?;
    assert_eq!(writes.len(), 1);
    history.committed(removal)?;
    assert!(history.channels.is_empty());
    assert_eq!(history.index_bytes, 0);
    Ok(())
}
