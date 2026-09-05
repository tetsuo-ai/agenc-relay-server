//! Startup reconstruction keeps immutable row metadata and releases message bodies.

use std::collections::BTreeMap;

use agenc_ircd_config::{Config, HistoryDefault, NodeRole};
use agenc_ircd_domain::{ContentPolicy, DomainState, HistoryPolicy, HistoryPosition};
use agenc_ircd_storage::{
    ExistingRecord, PersistentRecordValue, SealedRecord, StoragePort, StoredKey, TableId,
    logical_record_charge, validate_record_plaintext,
};

use agenc_ircd_storage::history_records::{
    HISTORY_CONTROL_KIND, HISTORY_MESSAGE_KIND, HistoryControlRecord, HistoryMessageRecord,
    HistoryRowReference,
};

use crate::RuntimeError;
use crate::budget::MemoryBudget;
use crate::state_core::durable::{DurableIndex, KeyDeriver};
use crate::state_core::reconstruct::scan_table;
use crate::sync::Arc;

use super::{
    DECODE_WORKING_CHARGE, HistoryChannel, HistoryRow, HistoryState, INDEX_ENTRY_CHARGE,
    MAX_CHANNELS, MAX_INDEX_BYTES, MAX_MESSAGES, MAX_TOTAL_BYTES, acquire, corrupt,
};

impl HistoryState {
    pub(crate) fn load(
        config: &Config,
        port: &StoragePort,
        keys: &KeyDeriver,
        domain: &DomainState,
        index: &mut DurableIndex,
        budget: Arc<MemoryBudget>,
    ) -> Result<Self, RuntimeError> {
        let default = match config.privacy.history_default {
            HistoryDefault::OneHour => HistoryPolicy::OneHour,
            HistoryDefault::OneDay => HistoryPolicy::TwentyFourHours,
            HistoryDefault::SevenDays => HistoryPolicy::SevenDays,
        };
        let mut history = Self {
            enabled: cfg!(feature = "history") && config.privacy.history_enabled,
            coordinator: config.network.role == NodeRole::Coordinator,
            default,
            maximum_bytes: MAX_TOTAL_BYTES.min(config.storage.database_max_bytes / 4),
            maximum_index_bytes: MAX_INDEX_BYTES.min(budget.capacity() / 8),
            budget,
            index_bytes: 0,
            message_count: 0,
            logical_bytes: 0,
            channels: BTreeMap::new(),
            queries: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        };
        scan_table(port, TableId::History, |key, bytes| {
            if !history.coordinator {
                return Err(corrupt());
            }
            history.load_row(&key, &bytes, keys)?;
            let sealed = SealedRecord::decode(&bytes)?;
            index.record_known(
                TableId::History,
                key,
                ExistingRecord::new(sealed.record_schema(), sealed.record_id()?, bytes.len())?,
            );
            Ok(())
        })?;
        history.validate_loaded(domain)?;
        Ok(history)
    }

    fn load_row(
        &mut self,
        key: &StoredKey,
        bytes: &[u8],
        keys: &KeyDeriver,
    ) -> Result<(), RuntimeError> {
        let _working = acquire(&self.budget, DECODE_WORKING_CHARGE)?;
        let sealed = SealedRecord::decode(bytes)?;
        let opened = keys.open(TableId::History, key, &sealed)?;
        validate_record_plaintext(
            TableId::History,
            key,
            sealed.record_schema(),
            opened.expose_for_storage_codec(),
        )?;
        let value =
            PersistentRecordValue::decode(TableId::History, opened.expose_for_storage_codec())?;
        match value.record_kind() {
            HISTORY_CONTROL_KIND => {
                self.insert_control(HistoryControlRecord::decode(value.body())?)?
            }
            HISTORY_MESSAGE_KIND => {
                let message = HistoryMessageRecord::decode(value.body())?;
                let logical_bytes = logical_record_charge(key.as_bytes().len(), bytes.len())?;
                self.insert_message(message, logical_bytes)?;
            }
            _ => return Err(corrupt()),
        }
        self.index_bytes = self
            .index_bytes
            .checked_add(INDEX_ENTRY_CHARGE)
            .ok_or(RuntimeError::Overflow)?;
        Ok(())
    }

    fn insert_control(&mut self, control: HistoryControlRecord) -> Result<(), RuntimeError> {
        if self.channels.len() >= MAX_CHANNELS || self.channels.contains_key(&control.channel_id) {
            return Err(corrupt());
        }
        let permit = self.reserve_index_entry()?;
        self.channels.insert(
            control.channel_id,
            HistoryChannel {
                control,
                rows: BTreeMap::new(),
                available_results: 0,
                _permit: permit,
            },
        );
        Ok(())
    }

    fn insert_message(
        &mut self,
        message: HistoryMessageRecord,
        logical_bytes: u64,
    ) -> Result<(), RuntimeError> {
        // Stored codecs permit the Unix epoch, while selection reserves timestamp zero.
        // Reject it before publishing metadata into the exact-size iterator.
        HistoryPosition::new(
            message.channel_sequence,
            message.message_id,
            message.received_unix_milliseconds,
        )
        .map_err(|_| corrupt())?;
        let permit = self.reserve_index_entry()?;
        let channel = self
            .channels
            .get_mut(&message.channel_id)
            .ok_or_else(corrupt)?;
        if channel.rows.contains_key(&message.channel_sequence) {
            return Err(corrupt());
        }
        channel.rows.insert(
            message.channel_sequence,
            HistoryRow {
                reference: row_reference(&message),
                logical_bytes,
                _permit: permit,
            },
        );
        self.message_count = self
            .message_count
            .checked_add(1)
            .ok_or(RuntimeError::Overflow)?;
        self.logical_bytes = self
            .logical_bytes
            .checked_add(logical_bytes)
            .ok_or(RuntimeError::Overflow)?;
        if self.message_count > MAX_MESSAGES || self.logical_bytes > self.maximum_bytes {
            return Err(RuntimeError::LimitExceeded);
        }
        Ok(())
    }

    fn validate_loaded(&self, domain: &DomainState) -> Result<(), RuntimeError> {
        for (id, channel) in &self.channels {
            validate_control_cut(&channel.control, domain.revision().get())?;
            let count = u64::try_from(channel.rows.len()).map_err(|_| RuntimeError::Overflow)?;
            let bytes = channel.rows.values().try_fold(0_u64, |sum, row| {
                sum.checked_add(row.logical_bytes)
                    .ok_or(RuntimeError::Overflow)
            })?;
            if count != channel.control.retained_message_count
                || bytes != channel.control.retained_logical_bytes
                || channel
                    .rows
                    .keys()
                    .next_back()
                    .is_some_and(|sequence| *sequence > channel.control.high_water_sequence)
            {
                return Err(corrupt());
            }
            if self.has_messages_or_purge(*id)
                && domain
                    .channel(*id)
                    .is_some_and(|current| current.content_policy() != ContentPolicy::Plaintext)
            {
                return Err(corrupt());
            }
        }
        self.require_live_controls(domain)?;
        Ok(())
    }

    fn require_live_controls(&self, domain: &DomainState) -> Result<(), RuntimeError> {
        if self.coordinator {
            for channel in domain.durable_channels() {
                if channel.history != HistoryPolicy::Off
                    && !self.channels.contains_key(&channel.channel_id)
                {
                    return Err(corrupt());
                }
            }
        }
        Ok(())
    }

    pub(super) fn reserve_index_entry(&self) -> Result<crate::budget::MemoryPermit, RuntimeError> {
        if self
            .index_bytes
            .checked_add(INDEX_ENTRY_CHARGE)
            .ok_or(RuntimeError::Overflow)?
            > self.maximum_index_bytes
        {
            return Err(RuntimeError::LimitExceeded);
        }
        acquire(&self.budget, INDEX_ENTRY_CHARGE)
    }
}

pub(super) fn row_reference(message: &HistoryMessageRecord) -> HistoryRowReference {
    HistoryRowReference {
        channel_sequence: message.channel_sequence,
        message_id: *message.message_id.as_bytes(),
        received_unix_milliseconds: message.received_unix_milliseconds,
        expires_unix_milliseconds: message.expires_unix_milliseconds,
    }
}

fn validate_control_cut(control: &HistoryControlRecord, revision: u64) -> Result<(), RuntimeError> {
    if control.history_authorization_generation > revision || control.high_water_sequence > revision
    {
        return Err(corrupt());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
