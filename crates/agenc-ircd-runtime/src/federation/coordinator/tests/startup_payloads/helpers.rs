//! Small sealed datasets drive the composed startup owner.
#![forbid(unsafe_code)]
use super::*;
use crate::bridge::StorageReadCompletionMessage;
use crate::state_core::durable::AccountServiceDurableWrite as Write;
use agenc_ircd_storage::e2ee_records::{
    MAILBOX_ROW_KIND, MAILBOX_SEQUENCE_ROW_KIND, MailboxKind, MailboxRow, MailboxSequenceRow,
};

pub(super) async fn commit(core: &mut StateCoreFixture, writes: Vec<Write>) -> TestResult {
    let context = core.context_mut()?;
    let plan = context.domain().plan_account_service_checkpoint()?;
    let writes = writes
        .into_iter()
        .map(|write| write.at_revision(plan.resulting_revision().get()))
        .collect::<Result<Vec<_>, _>>()?;
    context
        .stage_durable_with_account_service(
            plan,
            crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())?,
            None,
            0,
            writes,
        )
        .map_err(|e| format!("stage: {e:?}"))?;
    core.commit_staged_batch().await?;
    Ok(())
}

pub(super) fn mailbox(bytes: &[u8], kind: MailboxKind) -> TestResult<Vec<Write>> {
    let owner = MailboxSequenceRow::new([1; 32], [2; 16], kind, 1)?;
    let item = MailboxRow::Item {
        object_id: *ObjectId::compute(bytes).as_bytes(),
        conversation_id: [3; 32],
        inserted_at: 1,
        expires_at: 1000,
        grant: None,
    };
    let entries = [
        (owner.key()?, MAILBOX_SEQUENCE_ROW_KIND, owner.encode()?),
        (
            MailboxRow::item_key(&[1; 32], &[2; 16], kind, 0)?,
            MAILBOX_ROW_KIND,
            item.encode()?,
        ),
    ];
    entries
        .into_iter()
        .map(|(key, kind, body)| {
            let value =
                PersistentRecordValue::new(TableId::E2eeState, kind, 1, 0, None, Vec::new(), body)?;
            Ok(Write::put(TableId::E2eeState, key, value.encode()?)?)
        })
        .collect()
}

pub(super) async fn next(core: &mut StateCoreFixture) -> TestResult<StorageReadCompletionMessage> {
    tokio::time::timeout(std::time::Duration::from_secs(5), core.next_storage_read()).await?
}

pub(super) async fn drive(
    coordinator: &mut FederationCoordinator,
    core: &mut StateCoreFixture,
) -> TestResult {
    for _ in 0..64 {
        if coordinator.loaded() || coordinator.counters().violations != 0 {
            return Ok(());
        }
        let message = next(core).await?;
        assert!(coordinator.owns_storage_read(message.read_id));
        coordinator.storage_read_completed(core.context_mut()?, message);
    }
    Err("startup read bound".into())
}

pub(super) async fn object_read(
    coordinator: &mut FederationCoordinator,
    core: &mut StateCoreFixture,
) -> TestResult<StorageReadCompletionMessage> {
    for _ in 0..16 {
        let message = next(core).await?;
        if message.result.as_ref().is_ok_and(|result| {
            result
                .records
                .iter()
                .any(|row| row.table == TableId::E2eeObject)
        }) {
            return Ok(message);
        }
        coordinator.storage_read_completed(core.context_mut()?, message);
    }
    Err("no object read".into())
}
