//! Real storage receipts and index refresh for component state-machine tests.

use super::{BatchStep, CompletionStep, StateCore};
use crate::bridge::{StorageCompletionMessage, StorageReadCompletionMessage};
use crate::test_support::TestResult;
use tokio::sync::mpsc::Receiver;

impl StateCore {
    /// Closes the gather window and settles exactly one staged batch.
    pub(crate) async fn commit_fixture_batch(
        &mut self,
        storage: &mut Receiver<StorageCompletionMessage>,
        reads: &mut Receiver<StorageReadCompletionMessage>,
    ) -> TestResult {
        let step = self
            .context
            .submit_batch()
            .map_err(|e| format!("submit: {e:?}"))?;
        if !matches!(step, BatchStep::Submitted) {
            return Err("fixture batch was not submitted".into());
        }
        let completion = tokio::time::timeout(std::time::Duration::from_secs(5), storage.recv())
            .await?
            .ok_or("storage completion closed")?;
        let mut refresh = match self.step_completion(completion) {
            CompletionStep::Ready(None) => return Ok(()),
            CompletionStep::Ready(Some(exit)) => return Err(format!("commit: {exit:?}").into()),
            CompletionStep::Refresh(continuation) => self
                .start_index_refresh(continuation)
                .map_err(|e| format!("refresh: {e:?}"))?,
        };
        while let Some(pending) = refresh {
            let message = tokio::time::timeout(std::time::Duration::from_secs(5), reads.recv())
                .await?
                .ok_or("storage reads closed")?;
            if pending.owns(message.read_id) {
                refresh = self
                    .advance_index_refresh(pending, message)
                    .map_err(|e| format!("refresh receipt: {e:?}"))?;
            } else {
                self.router
                    .storage_read_completed(&mut self.context, message);
                refresh = Some(pending);
            }
        }
        Ok(())
    }
}
