//! Direct companion fixtures drive the same pinned recovery requests as the daemon.
#![forbid(unsafe_code)]

use super::*;
use crate::federation::coordinator::{CoordinatorConfig, FederationCoordinator};

pub(super) async fn outer(fixture: &mut RestartFixture) -> TestResult<FederationCoordinator> {
    let identity = &fixture.storage.identity;
    let mut coordinator = FederationCoordinator::new(
        CoordinatorConfig {
            network_id: identity.network_id,
            server_id: identity.server_id,
            server_name: SERVER_NAME.into(),
            recovery_epoch: identity.recovery_epoch,
            query_cursor_key: [21; 32],
            process_nonce: [22; 16],
            outbox_bytes_per_edge: 1 << 20,
            outbox_objects_per_edge: 64,
        },
        Vec::new(),
        std::sync::Arc::new(crate::test_support::TestChannelKeyVerifier),
        crate::bridge::crypto::ChannelKeyVerifierRecord::new([7; 16], [1; 32]),
    );
    coordinator.install_companion_executor(
        CompanionCoordinator::new(
            *identity.network_id.as_bytes(),
            identity.server_id,
            SERVER_NAME.into(),
        ),
        identity.server_incarnation,
    )?;
    coordinator.startup(fixture.storage.context_mut()?);
    for _ in 0..2048 {
        if coordinator.loaded() || coordinator.counters().violations != 0 {
            return Ok(coordinator);
        }
        let completion = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            fixture.storage.next_storage_read(),
        )
        .await??;
        assert!(coordinator.owns_storage_read(completion.read_id));
        coordinator.storage_read_completed(fixture.storage.context_mut()?, completion);
    }
    Err("startup read bound exceeded".into())
}

pub(super) async fn recover(
    fixture: &mut RestartFixture,
    restored: &mut CompanionCoordinator,
) -> TestResult {
    let context = fixture.storage.context_mut()?;
    let commit = context.head().storage_commit_sequence;
    let backing = context.backing_reservations();
    while let Some(request) = restored.next_restored_replay(&backing, commit)? {
        let _raw = backing.reserve(agenc_relay_storage::MAX_SEALED_RECORD_BYTES + 131_072)?;
        let _decode = backing.reserve(64 * 1024 * 1024)?;
        let id = fixture
            .storage
            .context_mut()?
            .submit_storage_read(request.plan()?)?;
        let completion = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            fixture.storage.next_storage_read(),
        )
        .await??;
        assert_eq!(completion.read_id, id);
        let result = completion.result?;
        assert_eq!(result.storage_commit_sequence, commit);
        assert!(result.records.len() <= request.record_limit());
        let mut values = Vec::new();
        let mut bytes = 0_usize;
        for record in &result.records {
            assert_eq!(record.table, request.table());
            assert!(record.sealed_record.len() <= request.sealed_record_limit());
            bytes += record.sealed_record.len();
            assert!(bytes <= request.sealed_page_limit());
            let plaintext = fixture.storage.context_mut()?.open_storage_plaintext(
                record.table,
                &record.key,
                &record.sealed_record,
            )?;
            let value =
                PersistentRecordValue::decode(record.table, plaintext.expose_for_storage_codec())?;
            values.push((record.key.clone(), value));
        }
        restored.admit_restored_replay(&request, commit, result.truncated, values)?;
    }
    Ok(())
}
