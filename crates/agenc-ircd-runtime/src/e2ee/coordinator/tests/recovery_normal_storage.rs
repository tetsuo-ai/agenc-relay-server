//! The route and its Normal declaration survive a real storage shutdown together.
#![forbid(unsafe_code)]
use super::*;
use crate::state_core::fanout::FanoutRequest;
use crate::test_support::StateCoreFixture;
use agenc_ircd_storage::{ReadPlan, StoredKey};

fn copy_writes(writes: &[Write]) -> TestResult<Vec<Write>> {
    writes
        .iter()
        .map(|write| {
            let (table, key, bytes) = write.encoded_record().ok_or("put")?;
            Ok(Write::put(table, key.clone(), bytes.to_vec())?)
        })
        .collect()
}

fn stage(core: &mut StateCoreFixture, writes: Vec<Write>) -> TestResult {
    let context = core.context_mut()?;
    let plan = context.domain().plan_account_service_checkpoint()?;
    let writes = writes
        .into_iter()
        .map(|write| write.at_revision(plan.resulting_revision().get()))
        .collect::<Result<Vec<_>, _>>()?;
    context
        .stage_durable_with_account_service(
            plan,
            FanoutRequest::new(Vec::new(), Vec::new())?,
            None,
            0,
            writes,
        )
        .map_err(|e| format!("stage: {e:?}"))?;
    Ok(())
}

async fn stored(
    core: &mut StateCoreFixture,
    table: TableId,
    key: &StoredKey,
) -> TestResult<Option<PersistentRecordValue>> {
    let read_id = core
        .context_mut()?
        .submit_storage_read(ReadPlan::exact(table, key.clone()))?;
    let message =
        tokio::time::timeout(std::time::Duration::from_secs(5), core.next_storage_read()).await??;
    assert_eq!(message.read_id, read_id);
    let result = message.result?;
    assert_eq!(
        result.storage_commit_sequence,
        core.context_mut()?.head().storage_commit_sequence
    );
    assert!(!result.truncated);
    assert!(result.records.len() <= 1);
    let Some(row) = result.records.first() else {
        return Ok(None);
    };
    assert_eq!(row.table, table);
    assert_eq!(row.key.as_bytes(), key.as_bytes());
    let opened = core
        .context_mut()?
        .open_storage_plaintext(table, key, &row.sealed_record)?;
    Ok(Some(PersistentRecordValue::decode(
        table,
        opened.expose_for_storage_codec(),
    )?))
}

#[tokio::test]
async fn normal_gate_and_route_share_a_receipt_and_reopen_after_a_lost_callback() -> TestResult {
    for apply_callback in [false, true] {
        let mut core = StateCoreFixture::with_registration_router(vec![71; 65_536])?;
        let mut fixture = binding()?;
        // The helper has reserved a route but has no live route or delivery stream.
        fixture.harness.coordinator.delivery_identity = None;
        fixture.harness.coordinator.configure_delivery_identity(
            core.identity.server_incarnation,
            core.identity.recovery_epoch,
        )?;
        stage(&mut core, copy_writes(&fixture.harness.writes)?)?;
        core.commit_staged_batch().await?;
        let gate_key = recovery_gate_key(&fixture.id)?;
        let route_key = RouteRow::key(&fixture.id)?;
        assert!(
            stored(&mut core, TableId::E2eeState, &gate_key)
                .await?
                .is_none()
        );
        assert!(
            stored(&mut core, TableId::E2eeState, &route_key)
                .await?
                .is_none()
        );
        let mut outcome = ok(evaluate_request(
            &mut fixture.harness,
            Op::BindGroup,
            &fixture.parameters,
            Some(&fixture.bytes),
        )?)?;
        let expected = written_gate(&outcome.writes, fixture.id)?.ok_or("gate")?;
        assert_eq!(expected.recovery_epoch(), core.identity.recovery_epoch);
        let commit_before = core.context_mut()?.head().storage_commit_sequence;
        stage(&mut core, copy_writes(&outcome.writes)?)?;
        assert_eq!(
            core.context_mut()?.head().storage_commit_sequence,
            commit_before
        );
        assert!(
            fixture
                .harness
                .coordinator
                .state
                .recovery_gates
                .get(&fixture.id)
                .is_none()
        );
        core.commit_staged_batch().await?;
        assert_eq!(
            core.context_mut()?.head().storage_commit_sequence,
            commit_before.checked_add(1).ok_or("commit")?
        );
        // The callback is deliberately optional: restart must recover a committed batch
        // even when the process never installed its private companion effects.
        if apply_callback {
            for effect in outcome.effects.drain(..) {
                effect(&mut fixture.harness.coordinator.state);
            }
            assert_eq!(
                fixture
                    .harness
                    .coordinator
                    .state
                    .recovery_gates
                    .get(&fixture.id),
                Some(expected)
            );
        }
        for write in &outcome.writes {
            fixture.harness.apply_logical_write(write)?;
        }
        drop(outcome);
        core.restart_registration_storage(vec![72; 65_536])?;
        let mut fresh = Harness::new()?;
        fresh.coordinator.delivery_identity = None;
        fresh.coordinator.configure_delivery_identity(
            core.identity.server_incarnation,
            core.identity.recovery_epoch,
        )?;
        for write in &fixture.harness.writes {
            let (table, key, _) = write.encoded_record().ok_or("put")?;
            let value = stored(&mut core, table, key)
                .await?
                .ok_or("committed row")?;
            fresh
                .coordinator
                .admit_restored_with_backing(table, key, &value, &fresh.backing);
        }
        fresh
            .coordinator
            .finish_restore_with_backing(fresh.backing.clone())?;
        assert_eq!(
            fresh.coordinator.state.recovery_gates.get(&fixture.id),
            Some(expected)
        );
        let route = fresh
            .coordinator
            .state
            .routes
            .route(&ConversationId(fixture.id))
            .ok_or("route")?;
        assert_eq!(route.recovery, RecoveryState::Normal);
        let value = stored(&mut core, TableId::E2eeState, &route_key)
            .await?
            .ok_or("route row")?;
        let row = RouteRow::decode(value.body())?;
        assert!(!row.recovery_gate);
        assert_eq!(&row.binding_id, expected.restored_binding_id().as_bytes());
        assert_eq!(
            &row.accepted_state_id,
            expected.restored_accepted_state_id().as_bytes()
        );
        assert_eq!(
            &row.sequencer_head_id,
            expected.restored_sequencer_head_id().as_bytes()
        );
    }
    Ok(())
}
