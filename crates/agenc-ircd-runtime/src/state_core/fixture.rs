//! Real storage receipts and index refresh for component state-machine tests.

use super::{BatchStep, CompletionStep, StateCore};
use crate::bridge::{StorageCompletionMessage, StorageReadCompletionMessage};
use crate::test_support::TestResult;
use tokio::sync::mpsc::Receiver;

impl StateCore {
    /// Rejects a gather batch before it reaches the storage owner.
    pub(crate) fn reject_fixture_batch_before_submission(
        &mut self,
        error: agenc_ircd_storage::StorageError,
    ) -> TestResult {
        if self.context.in_flight() {
            return Err("cannot reject a submitted fixture batch".into());
        }
        let batch = self.context.pending.take().ok_or("no fixture batch")?;
        let rejected = self.context.reject_batch(batch, error);
        self.report_rejections(rejected);
        Ok(())
    }

    /// Closes the gather window and settles exactly one staged batch.
    ///
    /// The receipts are awaited without a wall-clock deadline. The storage
    /// owner is a real thread doing real `fsync`, so how long a large batch
    /// takes depends on the host: a five-second bound here failed six
    /// `delivery_restart` tests on every round of a CPU-saturated machine
    /// while the commit was still making progress (QA-04, issue #175). A
    /// storage owner that stops instead closes its channel, which ends the
    /// wait with an error, so no deadline is needed to observe a failure.
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
        let completion = storage.recv().await.ok_or("storage completion closed")?;
        let mut refresh = match self.step_completion(completion) {
            CompletionStep::Ready(None) => return Ok(()),
            CompletionStep::Ready(Some(exit)) => return Err(format!("commit: {exit:?}").into()),
            CompletionStep::Refresh(continuation) => self
                .start_index_refresh(continuation)
                .map_err(|e| format!("refresh: {e:?}"))?,
        };
        while let Some(pending) = refresh {
            let message = reads.recv().await.ok_or("storage reads closed")?;
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
