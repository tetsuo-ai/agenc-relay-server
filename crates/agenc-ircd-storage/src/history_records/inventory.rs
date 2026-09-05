//! Constant-memory verification of sorted durable history accounting.

use super::{HistoryControlRecord, HistoryMessageRecord};
use crate::{PersistentRecordValue, StorageError, StoredKey, TableId, logical_record_charge};

const MAX_CONTROLS: u64 = 4_096;
const MAX_MESSAGES: u64 = 262_144;
const MAX_LOGICAL_BYTES: u64 = 1_073_741_824;

pub(crate) struct HistoryInventory {
    current: Option<HistoryControlRecord>,
    count: u64,
    bytes: u64,
    last_sequence: u64,
    controls: u64,
    messages: u64,
    total_bytes: u64,
    byte_limit: u64,
}

impl HistoryInventory {
    pub(crate) fn new(byte_limit: u64) -> Self {
        Self {
            current: None,
            count: 0,
            bytes: 0,
            last_sequence: 0,
            controls: 0,
            messages: 0,
            total_bytes: 0,
            byte_limit: byte_limit.min(MAX_LOGICAL_BYTES),
        }
    }

    pub(crate) fn observe(
        &mut self,
        table: TableId,
        key: &StoredKey,
        sealed_bytes: usize,
        plaintext: &[u8],
    ) -> Result<(), StorageError> {
        if table != TableId::History {
            return Ok(());
        }
        let value = PersistentRecordValue::decode(table, plaintext)?;
        super::validate_binding(key, &value)?;
        if value.record_kind() == super::HISTORY_CONTROL_KIND {
            self.finish_channel()?;
            let control = HistoryControlRecord::decode(value.body())?;
            if self
                .current
                .as_ref()
                .is_some_and(|last| last.channel_id >= control.channel_id)
            {
                return Err(StorageError::StaleState);
            }
            self.controls = self.controls.checked_add(1).ok_or(StorageError::Overflow)?;
            if self.controls > MAX_CONTROLS {
                return Err(StorageError::LimitExceeded);
            }
            self.current = Some(control);
            self.count = 0;
            self.bytes = 0;
            self.last_sequence = 0;
            return Ok(());
        }
        self.observe_message(
            HistoryMessageRecord::decode(value.body())?,
            logical_record_charge(key.as_bytes().len(), sealed_bytes)?,
        )
    }

    fn observe_message(
        &mut self,
        message: HistoryMessageRecord,
        charge: u64,
    ) -> Result<(), StorageError> {
        let control = self.current.as_ref().ok_or(StorageError::StaleState)?;
        if message.channel_id != control.channel_id
            || message.channel_sequence <= self.last_sequence
            || message.channel_sequence > control.high_water_sequence
        {
            return Err(StorageError::StaleState);
        }
        self.count = self.count.checked_add(1).ok_or(StorageError::Overflow)?;
        self.bytes = self
            .bytes
            .checked_add(charge)
            .ok_or(StorageError::Overflow)?;
        self.messages = self.messages.checked_add(1).ok_or(StorageError::Overflow)?;
        self.total_bytes = self
            .total_bytes
            .checked_add(charge)
            .ok_or(StorageError::Overflow)?;
        self.last_sequence = message.channel_sequence;
        if self.messages > MAX_MESSAGES || self.total_bytes > self.byte_limit {
            return Err(StorageError::LimitExceeded);
        }
        Ok(())
    }

    fn finish_channel(&self) -> Result<(), StorageError> {
        if self.current.as_ref().is_some_and(|control| {
            control.retained_message_count != self.count
                || control.retained_logical_bytes != self.bytes
        }) {
            return Err(StorageError::StaleState);
        }
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<(), StorageError> {
        self.finish_channel()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agenc_ircd_domain::federation::SourceView;
    use agenc_ircd_domain::{ChannelNameValue, MessageKind, NicknameValue};
    use agenc_ircd_types::{ChannelInstanceId, MessageId, PublicCloak, UserId};

    fn message() -> Result<HistoryMessageRecord, StorageError> {
        Ok(HistoryMessageRecord {
            channel_id: ChannelInstanceId::from_bytes([1; 16]),
            channel_sequence: 7,
            message_id: MessageId::from_bytes([2; 16]),
            received_unix_milliseconds: 1_000,
            expires_unix_milliseconds: 3_601_000,
            retention_seconds: 3_600,
            channel_name: ChannelNameValue::parse("#history")
                .map_err(|_| StorageError::InvalidEncoding)?,
            sender: SourceView {
                user_id: UserId::from_bytes([3; 16]),
                nickname: NicknameValue::parse("Alice")
                    .map_err(|_| StorageError::InvalidEncoding)?,
                public_cloak: PublicCloak::from_components(*b"aaaaaaaaaa", *b"bbbbbbbbbbbbbbbb")
                    .map_err(|_| StorageError::InvalidEncoding)?,
                account_label: None,
            },
            kind: MessageKind::Privmsg,
            tags: Vec::new(),
            body: "kept message".into(),
        })
    }

    fn observe_control(
        inventory: &mut HistoryInventory,
        control: &HistoryControlRecord,
    ) -> Result<(), StorageError> {
        let key = super::super::history_control_key(control.channel_id)?;
        let value = PersistentRecordValue::new(
            TableId::History,
            2,
            7,
            0,
            None,
            Vec::new(),
            control.encode()?,
        )?
        .encode()?;
        inventory.observe(
            TableId::History,
            &key,
            value.len() + crate::MIN_SEALED_RECORD_BYTES,
            &value,
        )
    }

    #[test]
    fn inventory_counts_physically_present_expired_rows_and_rejects_orphans_and_missing_rows()
    -> Result<(), StorageError> {
        let message = message()?;
        let key = super::super::history_message_key(message.channel_id, message.channel_sequence)?;
        let value = PersistentRecordValue::new(
            TableId::History,
            1,
            7,
            0,
            Some(3_601),
            Vec::new(),
            message.encode()?,
        )?
        .encode()?;
        let sealed_bytes = value.len() + crate::MIN_SEALED_RECORD_BYTES;
        let mut control = HistoryControlRecord::empty(message.channel_id, 7)?;
        control.high_water_sequence = 7;
        control.retained_message_count = 1;
        control.retained_logical_bytes = logical_record_charge(24, sealed_bytes)?;
        let mut valid = HistoryInventory::new(MAX_LOGICAL_BYTES);
        observe_control(&mut valid, &control)?;
        valid.observe(TableId::History, &key, sealed_bytes, &value)?;
        valid.finish()?;
        let mut orphan = HistoryInventory::new(MAX_LOGICAL_BYTES);
        assert!(
            orphan
                .observe(TableId::History, &key, sealed_bytes, &value)
                .is_err()
        );
        let mut missing = HistoryInventory::new(MAX_LOGICAL_BYTES);
        observe_control(&mut missing, &control)?;
        assert!(missing.finish().is_err());
        control.retained_logical_bytes += 1;
        let mut wrong_count = HistoryInventory::new(MAX_LOGICAL_BYTES);
        observe_control(&mut wrong_count, &control)?;
        wrong_count.observe(TableId::History, &key, sealed_bytes, &value)?;
        assert!(wrong_count.finish().is_err());
        Ok(())
    }

    #[test]
    fn inventory_bounds_empty_controls_without_retaining_all_channel_metadata()
    -> Result<(), StorageError> {
        let mut inventory = HistoryInventory::new(MAX_LOGICAL_BYTES);
        for number in 1_u128..=4_096 {
            observe_control(
                &mut inventory,
                &HistoryControlRecord::empty(
                    ChannelInstanceId::from_bytes(number.to_be_bytes()),
                    1,
                )?,
            )?;
        }
        let excess = HistoryControlRecord::empty(
            ChannelInstanceId::from_bytes(4_097_u128.to_be_bytes()),
            1,
        )?;
        assert_eq!(
            observe_control(&mut inventory, &excess),
            Err(StorageError::LimitExceeded)
        );
        Ok(())
    }
}
