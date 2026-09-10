//! Receipt and sealed-read helpers expose the actual committed state.
#![forbid(unsafe_code)]
use super::*;
use agenc_ircd_storage::e2ee_records::origin::OriginSequenceKey;
use agenc_ircd_storage::{ReadPlan, StoredKey};

impl Fixture {
    pub(in super::super) fn executor(&self) -> TestResult<&CompanionCoordinator> {
        self.coordinator
            .companion_executor()
            .ok_or_else(|| "executor".into())
    }
    pub(in super::super) fn origin_key(&self) -> CompanionOriginKey {
        CompanionOriginKey {
            home_server_id: self.key.home_server_id,
            server_incarnation: self.key.server_incarnation,
            origin_id: self.key.origin_id,
        }
    }
    pub(in super::super) fn floor_key(&self) -> TestResult<StoredKey> {
        Ok(OriginSequenceRow::key(&OriginSequenceKey {
            home_server_id: self.key.home_server_id,
            server_incarnation: self.key.server_incarnation,
            origin_id: self.key.origin_id,
        })?)
    }
    pub(in super::super) fn retry(&mut self) -> TestResult {
        let now = self.core.context_mut()?.now().get();
        self.core
            .context_mut()?
            .set_monotonic_for_test(now.checked_add(1000).ok_or("tick")?);
        self.idle()
    }
    pub(in super::super) async fn commit(&mut self) -> TestResult {
        assert!(self.coordinator.pending.is_some());
        self.core.commit_staged_batch().await?;
        self.coordinator.batch_applied(self.core.context_mut()?);
        assert!(self.coordinator.loaded());
        assert_eq!(self.coordinator.counters().violations, 0);
        Ok(())
    }
    pub(in super::super) async fn restart(&mut self) -> TestResult {
        self.coordinator = empty_coordinator(&self.core)?;
        self.coordinator.startup(self.core.context_mut()?);
        helpers::drive(&mut self.coordinator, &mut self.core).await?;
        assert!(self.coordinator.loaded());
        assert_eq!(self.coordinator.counters().violations, 0);
        Ok(())
    }
    pub(in super::super) async fn stored(
        &mut self,
        table: TableId,
        key: StoredKey,
    ) -> TestResult<Option<PersistentRecordValue>> {
        let id = self
            .core
            .context_mut()?
            .submit_storage_read(ReadPlan::exact(table, key.clone()))?;
        let message = helpers::next(&mut self.core).await?;
        assert_eq!(message.read_id, id);
        let result = message.result?;
        assert_eq!(
            result.storage_commit_sequence,
            self.core.context_mut()?.head().storage_commit_sequence
        );
        assert!(!result.truncated);
        assert!(result.records.len() <= 1);
        let Some(row) = result.records.first() else {
            return Ok(None);
        };
        assert_eq!(row.table, table);
        assert!(row.key == key);
        let opened =
            self.core
                .context_mut()?
                .open_storage_plaintext(table, &key, &row.sealed_record)?;
        Ok(Some(PersistentRecordValue::decode(
            table,
            opened.expose_for_storage_codec(),
        )?))
    }
}
