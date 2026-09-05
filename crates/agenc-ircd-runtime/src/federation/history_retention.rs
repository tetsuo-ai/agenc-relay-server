//! Bounded metadata retirement after a conservative origin-deletion retention interval.

use agenc_ircd_storage::history_records::{
    HISTORY_COORDINATOR_RESULT_KIND, HISTORY_EDGE_REQUEST_KIND, HistoryCoordinatorResultRecord,
    HistoryEdgeRequestRecord,
};
use agenc_ircd_storage::{PersistentRecordValue, ReadPlan, ReadResult, StoredKey, TableId};

use crate::RuntimeError;
use crate::bridge::StorageReadId;
use crate::state_core::StateCoreContext;
use crate::state_core::durable::AccountServiceDurableWrite;

const PAGE_ROWS: u16 = 256;
const RETENTION_SECONDS: u64 = 86_400;

#[derive(Default)]
pub(crate) struct Retention {
    pending: Option<StorageReadId>,
    start: Option<StoredKey>,
}

pub(crate) struct Cleanup {
    pub(crate) writes: Vec<AccountServiceDurableWrite>,
    pub(crate) deleted: Vec<[u8; 64]>,
    pub(crate) deleted_available_channels: Vec<agenc_ircd_types::ChannelInstanceId>,
    next: Option<StoredKey>,
}

impl Retention {
    pub(crate) fn owns(&self, read: StorageReadId) -> bool {
        self.pending == Some(read)
    }

    pub(crate) fn begin(&mut self, context: &mut StateCoreContext) {
        if self.pending.is_some() || context.pending_len() != 0 || !context.history_clock_safe() {
            return;
        }
        let start = self.start.clone().or_else(|| StoredKey::new(vec![0]).ok());
        let Some(start) = start else {
            return;
        };
        let plan = StoredKey::new(vec![255; agenc_ircd_storage::MAX_STORED_KEY_BYTES])
            .and_then(|end| ReadPlan::range(TableId::RequestResult, start, end, PAGE_ROWS));
        self.pending = plan
            .ok()
            .and_then(|plan| context.submit_storage_read(plan).ok());
    }

    pub(crate) fn completed(&mut self) {
        self.pending = None;
    }

    pub(crate) fn committed(&mut self, cleanup: &Cleanup) {
        self.start = cleanup.next.clone();
    }

    pub(crate) fn prepare(
        &self,
        context: &StateCoreContext,
        result: &ReadResult,
        revision: u64,
        kind: u16,
        terminal: impl Fn(&[u8; 64]) -> bool,
    ) -> Result<Cleanup, RuntimeError> {
        if !context.history_clock_safe() || result.records.len() > usize::from(PAGE_ROWS) {
            return Err(RuntimeError::InvalidValue);
        }
        let now = context
            .utc_now()
            .map_err(|_| RuntimeError::InvalidValue)?
            .get();
        let mut cleanup = Cleanup {
            writes: Vec::new(),
            deleted: Vec::new(),
            deleted_available_channels: Vec::new(),
            next: None,
        };
        for row in &result.records {
            let opened = context.open_storage_plaintext(
                TableId::RequestResult,
                &row.key,
                &row.sealed_record,
            )?;
            let value = PersistentRecordValue::decode(
                TableId::RequestResult,
                opened.expose_for_storage_codec(),
            )?;
            if value.record_kind() != kind {
                continue;
            }
            let key: [u8; 64] = row
                .key
                .as_bytes()
                .try_into()
                .map_err(|_| RuntimeError::InvalidValue)?;
            if !terminal(&key) {
                continue;
            }
            if value.expires_at().is_some_and(|deadline| deadline <= now) {
                cleanup.writes.push(AccountServiceDurableWrite::delete(
                    TableId::RequestResult,
                    row.key.clone(),
                )?);
                cleanup.deleted.push(key);
                if let Some(channel) = available_channel(kind, value.body())? {
                    cleanup.deleted_available_channels.push(channel);
                }
            } else if value.expires_at().is_none() {
                let body = retired_body(kind, value.body())?;
                let deadline = now
                    .checked_add(RETENTION_SECONDS)
                    .ok_or(RuntimeError::Overflow)?;
                let value = PersistentRecordValue::new(
                    TableId::RequestResult,
                    kind,
                    revision,
                    0,
                    Some(deadline),
                    Vec::new(),
                    body,
                )?
                .encode()?;
                cleanup.writes.push(AccountServiceDurableWrite::put(
                    TableId::RequestResult,
                    row.key.clone(),
                    value,
                )?);
            }
        }
        if result.truncated {
            let mut last = result
                .records
                .last()
                .ok_or(RuntimeError::InvalidValue)?
                .key
                .as_bytes()
                .to_vec();
            last.push(0);
            cleanup.next = Some(StoredKey::new(last)?);
        }
        Ok(cleanup)
    }
}

fn retired_body(kind: u16, body: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    match kind {
        HISTORY_COORDINATOR_RESULT_KIND => HistoryCoordinatorResultRecord::decode(body)?
            .encode()
            .map_err(Into::into),
        HISTORY_EDGE_REQUEST_KIND => {
            let mut record = HistoryEdgeRequestRecord::decode(body)?;
            record.sink_gone = true;
            record.encode().map_err(Into::into)
        }
        _ => Err(RuntimeError::InvalidValue),
    }
}

fn available_channel(
    kind: u16,
    body: &[u8],
) -> Result<Option<agenc_ircd_types::ChannelInstanceId>, RuntimeError> {
    if kind != HISTORY_COORDINATOR_RESULT_KIND {
        return Ok(None);
    }
    let record = HistoryCoordinatorResultRecord::decode(body)?;
    Ok(
        (record.status == agenc_ircd_storage::history_records::HistoryResultStatus::Available)
            .then(|| agenc_ircd_types::ChannelInstanceId::from_bytes(record.page.channel_id)),
    )
}
