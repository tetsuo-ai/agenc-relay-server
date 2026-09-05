//! Coordinator history metadata, durable admission, and bounded authenticated reads.

mod capture;
mod index;
mod maintenance;
mod query;

use std::collections::BTreeMap;

use agenc_ircd_domain::{HistoryPolicy, HistoryPosition};
use agenc_ircd_storage::history_records::{HistoryControlRecord, HistoryRowReference};
use agenc_ircd_types::ChannelInstanceId;

use crate::RuntimeError;
use crate::budget::{
    BoundedMemoryCharges, MemoryBudget, MemoryBudgetPort, MemoryCharge, MemoryPermit,
};
use crate::sync::Arc;

pub(crate) use capture::HistoryMutation;
pub(crate) use query::{HISTORY_PAGE_MESSAGES, HistoryMaterialized, HistorySnapshot};

const MAX_CHANNELS: usize = 4_096;
const MAX_MESSAGES: u64 = 262_144;
const MAX_CHANNEL_MESSAGES: u64 = 65_536;
const MAX_CHANNEL_BYTES: u64 = 67_108_864;
const MAX_TOTAL_BYTES: u64 = 1_073_741_824;
const MAX_INDEX_BYTES: u64 = 268_435_456;
// Two separately charged backing allowances cover the metadata entry and its
// corresponding DurableIndex entry, including stored-key ownership. BTreeMap
// nodes are conservatively charged per entry rather than relying on std layout.
const INDEX_ENTRY_CHARGE: u64 = 8_192;
const DECODE_WORKING_CHARGE: u64 = 262_144;
const CONTROL_WORKING_CHARGE: u64 = 32_768;

pub(crate) struct HistoryState {
    enabled: bool,
    coordinator: bool,
    default: HistoryPolicy,
    budget: Arc<MemoryBudget>,
    maximum_bytes: u64,
    maximum_index_bytes: u64,
    index_bytes: u64,
    message_count: u64,
    logical_bytes: u64,
    channels: BTreeMap<ChannelInstanceId, HistoryChannel>,
    queries: Arc<std::sync::atomic::AtomicUsize>,
}

struct HistoryChannel {
    control: HistoryControlRecord,
    rows: BTreeMap<u64, HistoryRow>,
    available_results: u64,
    _permit: MemoryPermit,
}

struct HistoryRow {
    reference: HistoryRowReference,
    logical_bytes: u64,
    _permit: MemoryPermit,
}

#[cfg(all(test, feature = "history"))]
impl crate::state_core::StateCoreContext {
    pub(crate) fn enable_history_for_test(&mut self, coordinator: bool) {
        self.history = Some(HistoryState {
            enabled: cfg!(feature = "history"),
            coordinator,
            default: HistoryPolicy::TwentyFourHours,
            maximum_bytes: MAX_TOTAL_BYTES,
            maximum_index_bytes: MAX_INDEX_BYTES.min(self.budget.capacity() / 8),
            budget: Arc::clone(&self.budget),
            index_bytes: 0,
            message_count: 0,
            logical_bytes: 0,
            channels: BTreeMap::new(),
            queries: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        });
    }
}

impl HistoryRow {
    fn position(&self) -> Result<HistoryPosition, RuntimeError> {
        HistoryPosition::new(
            self.reference.channel_sequence,
            agenc_ircd_types::MessageId::from_bytes(self.reference.message_id),
            self.reference.received_unix_milliseconds,
        )
        .map_err(|_| corrupt())
    }
}

fn acquire(budget: &MemoryBudget, bytes: u64) -> Result<MemoryPermit, RuntimeError> {
    let mut batch =
        budget.try_acquire_batch(BoundedMemoryCharges::new(&[MemoryCharge::fixed(bytes)])?)?;
    batch.split_exact(bytes).ok_or(RuntimeError::InvalidValue)
}

fn corrupt() -> RuntimeError {
    RuntimeError::Storage(agenc_ircd_storage::StorageError::StaleState)
}

fn retention_seconds(policy: HistoryPolicy) -> Option<u32> {
    match policy {
        HistoryPolicy::Off => None,
        HistoryPolicy::OneHour => Some(3_600),
        HistoryPolicy::TwentyFourHours => Some(86_400),
        HistoryPolicy::SevenDays => Some(604_800),
    }
}
