//! Idle expiry uses committed mailbox metadata even when no peer is connected.
#![forbid(unsafe_code)]

use super::*;
mod cases;
mod fixture;
use crate::state_core::durable::AccountServiceDurableWrite as Write;
use agenc_ircd_storage::e2ee_records::{
    MAILBOX_ROW_KIND, MAILBOX_SEQUENCE_ROW_KIND, MailboxKind, MailboxRow, MailboxSequenceRow,
};

#[tokio::test]
async fn idle_timer_retires_an_expired_durable_mailbox_item() -> TestResult {
    let mut core = StateCoreFixture::with_registration_router(entropy_script())?;
    core.context_mut()?.set_wall_for_test(2000);
    let network = *core.identity.network_id.as_bytes();
    let bytes = application(network)?;
    let id = *ObjectId::compute(&bytes).as_bytes();
    let conversation_id = agenc_ircd_e2ee::ids::conversation_id(&network, &[33; 32])?;
    let owner = MailboxSequenceRow::new([1; 32], [2; 16], MailboxKind::Application, 1)?;
    let item = MailboxRow::Item {
        object_id: id,
        conversation_id,
        inserted_at: 1,
        expires_at: 1000,
        grant: None,
    };
    let mut writes =
        vec![CompanionCoordinator::object_write(&bytes).map_err(|e| format!("object: {e:?}"))?];
    for (key, kind, body) in [
        (owner.key()?, MAILBOX_SEQUENCE_ROW_KIND, owner.encode()?),
        (
            MailboxRow::item_key(&[1; 32], &[2; 16], MailboxKind::Application, 0)?,
            MAILBOX_ROW_KIND,
            item.encode()?,
        ),
    ] {
        let value =
            PersistentRecordValue::new(TableId::E2eeState, kind, 1, 0, None, Vec::new(), body)?;
        writes.push(Write::put(TableId::E2eeState, key, value.encode()?)?);
    }
    helpers::commit(&mut core, writes).await?;
    let commit = core.context_mut()?.head().storage_commit_sequence;
    let mut coordinator = empty_coordinator(&core)?;
    coordinator.startup(core.context_mut()?);
    helpers::drive(&mut coordinator, &mut core).await?;
    assert!(coordinator.loaded());
    assert_eq!(coordinator.counters().violations, 0);
    assert_eq!(core.context_mut()?.head().storage_commit_sequence, commit);
    let executor = coordinator.companion_executor().ok_or("executor")?;
    assert_eq!(executor.state.mailboxes.item_count(), 1);
    assert_eq!(executor.state.objects.get(&id), Some(&bytes));
    let context = core.context_mut()?;
    let now = context.now();
    for _ in 0..32 {
        let Some(entry) = context.timers_mut().pop_due(now) else {
            break;
        };
        coordinator.timer_fired(context, entry);
        if coordinator.pending.is_some() {
            break;
        }
    }
    assert!(
        coordinator.pending.is_some(),
        "idle maintenance left an expired durable item and its payload resident"
    );
    let budget = core.context_mut()?.backing_budget_for_test();
    let charged = budget.charged();
    coordinator.batch_applied(core.context_mut()?);
    assert!(
        coordinator.pending.is_some(),
        "an earlier callback consumed the new receipt owner"
    );
    core.commit_staged_batch().await?;
    assert_eq!(
        coordinator
            .companion_executor()
            .ok_or("executor")?
            .state
            .mailboxes
            .item_count(),
        1
    );
    coordinator.batch_applied(core.context_mut()?);
    let executor = coordinator.companion_executor().ok_or("executor")?;
    assert_eq!(executor.state.mailboxes.item_count(), 0);
    assert!(!executor.state.objects.contains_key(&id));
    assert_eq!(executor.state.object_bytes, 0);
    assert!(executor.state.object_memory.is_empty());
    assert!(budget.charged() < charged);
    assert!(
        fixture::stored(
            &mut core,
            TableId::E2eeState,
            MailboxRow::item_key(&[1; 32], &[2; 16], MailboxKind::Application, 0)?
        )
        .await?
        .is_none()
    );
    let stored_owner = fixture::stored(&mut core, TableId::E2eeState, owner.key()?)
        .await?
        .ok_or("sequence owner")?;
    assert_eq!(MailboxSequenceRow::decode(stored_owner.body())?, owner);
    let object = fixture::stored(
        &mut core,
        TableId::E2eeObject,
        agenc_ircd_storage::StoredKey::new(id.to_vec())?,
    )
    .await?
    .ok_or("stored object")?;
    assert_eq!(
        agenc_ircd_storage::e2ee_records::ObjectRow::decode(object.body())?.bytes,
        bytes
    );
    drop(coordinator);
    let mut coordinator = empty_coordinator(&core)?;
    coordinator.startup(core.context_mut()?);
    helpers::drive(&mut coordinator, &mut core).await?;
    assert!(coordinator.loaded());
    let executor = coordinator.companion_executor().ok_or("executor")?;
    assert_eq!(executor.state.mailboxes.item_count(), 0);
    assert!(!executor.state.objects.contains_key(&id));
    Ok(())
}
