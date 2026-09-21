//! Real storage restart must not discard an orphan declared recovery record.
#![forbid(unsafe_code)]
use super::*;
use crate::state_core::durable::AccountServiceDurableWrite as Write;
use agenc_relay_crypto::StorageDigest;
use agenc_relay_storage::e2ee_records::{RECOVERY_GATE_KIND, recovery_gate_key};
use agenc_relay_storage::{E2eeRecoveryGate, E2eeRecoveryKind};

#[tokio::test]
async fn reopened_storage_refuses_every_orphan_recovery_gate_without_publishing() -> TestResult {
    for kind in [
        E2eeRecoveryKind::Normal,
        E2eeRecoveryKind::Pending,
        E2eeRecoveryKind::Closed,
        E2eeRecoveryKind::Conflict,
    ] {
        let mut core = StateCoreFixture::with_registration_router(entropy_script())?;
        let mut control = empty_coordinator(&core)?;
        control.startup(core.context_mut()?);
        helpers::drive(&mut control, &mut core).await?;
        assert!(control.loaded());
        assert_eq!(control.counters().violations, 0);
        drop(control);
        let conversation = [201; 32];
        let row = E2eeRecoveryGate::new(
            StorageDigest::from_bytes(conversation),
            kind,
            core.identity.recovery_epoch,
            StorageDigest::from_bytes([202; 32]),
            StorageDigest::from_bytes([203; 32]),
            StorageDigest::from_bytes([204; 32]),
            StorageDigest::from_bytes([205; 32]),
        );
        let key = recovery_gate_key(&conversation)?;
        let value = PersistentRecordValue::new(
            TableId::E2eeState,
            RECOVERY_GATE_KIND,
            1,
            0,
            None,
            Vec::new(),
            row.encode()?,
        )?;
        helpers::commit(
            &mut core,
            vec![Write::put(
                TableId::E2eeState,
                key.clone(),
                value.encode()?,
            )?],
        )
        .await?;
        core.restart_registration_storage(entropy_script())?;
        let head = core.context_mut()?.head().storage_commit_sequence;
        let budget = core.context_mut()?.backing_budget_for_test();
        let baseline = budget.charged();
        let mut coordinator = empty_coordinator(&core)?;
        coordinator.startup(core.context_mut()?);
        let mut seen = false;
        for _ in 0..32 {
            if coordinator.loaded() || coordinator.counters().violations != 0 {
                break;
            }
            let message = helpers::next(&mut core).await?;
            for stored in &message
                .result
                .as_ref()
                .map_err(|e| format!("read: {e:?}"))?
                .records
            {
                if stored.table == TableId::E2eeState && stored.key == key {
                    let bytes = core.context_mut()?.open_storage_plaintext(
                        stored.table,
                        &stored.key,
                        &stored.sealed_record,
                    )?;
                    let value = PersistentRecordValue::decode(
                        stored.table,
                        bytes.expose_for_storage_codec(),
                    )?;
                    assert_eq!(E2eeRecoveryGate::decode(value.body())?, row);
                    seen = true;
                }
            }
            assert!(coordinator.owns_storage_read(message.read_id));
            coordinator.storage_read_completed(core.context_mut()?, message);
        }
        assert!(seen);
        assert!(!coordinator.loaded(), "orphan {kind:?} gate was discarded");
        assert_eq!(coordinator.counters().violations, 1);
        assert_eq!(core.context_mut()?.head().storage_commit_sequence, head);
        assert!(
            coordinator
                .companion_executor()
                .ok_or("executor")?
                .state
                .recovery_gates
                .get(&conversation)
                .is_none()
        );
        drop(coordinator);
        assert_eq!(budget.charged(), baseline);
    }
    Ok(())
}
